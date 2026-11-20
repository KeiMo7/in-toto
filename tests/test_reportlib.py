# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_reportlib.py

<Purpose>
  Tests for the machine-consumable verification report
  (``in_toto.reportlib``) and its same-source integration into
  ``in_toto.verifylib``.
"""

import glob
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import in_toto.reportlib
from in_toto import verifylib
from in_toto.exceptions import (
    BadReturnValueError,
    LinkNotFoundError,
    RuleVerificationError,
)
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.reportlib import (
    ARTIFACT_TYPES,
    CATEGORIES,
    ITEM_TYPES,
    MAX_FINDINGS,
    RESULTS,
    STAGES,
    VerificationFinding,
    VerificationReport,
    _join_path,
)
from in_toto.verifylib import (
    in_toto_verify,
    in_toto_verify_with_report,
    verify_disallow_rule,
    verify_item_rules,
    verify_require_rule,
    verify_threshold_constraints,
)
from tests.common import SignerStore, TmpDirMixin, VersionedPython


def _make_link(step_name, signer, materials=None, products=None):
    """Create and sign a link metadata container."""
    link = Metablock(
        signed=Link(
            name=step_name,
            materials=materials or {},
            products=products or {},
        )
    )
    link.create_signature(signer)
    return link


def _make_layout(signer, pub_key, steps=None, inspect=None):
    """Create and sign a layout metadata container."""
    layout = Layout(
        keys={pub_key["keyid"]: pub_key},
        steps=steps or [],
        inspect=inspect or [],
    )
    metadata = Metablock(signed=layout)
    metadata.create_signature(signer)
    return metadata


class TestReportPrimitives(unittest.TestCase):
    """Tests for reportlib data structures and value domains."""

    def test_closed_value_domains(self):
        """Categorical fields expose a closed set of stable values."""
        category_names = sorted(
            name for name in dir(CATEGORIES) if not name.startswith("_")
        )
        category_values = sorted(
            getattr(CATEGORIES, name) for name in category_names
        )
        self.assertEqual(
            category_names,
            [
                "COMMAND_RETURN_VALUE",
                "MATERIAL_MISSING",
                "RULE_FAILURE",
                "SIGNATURE_THRESHOLD",
                "UNKNOWN",
            ],
        )
        self.assertEqual(
            category_values,
            [
                "command_return_value",
                "material_missing",
                "rule_failure",
                "signature_threshold",
                "unknown",
            ],
        )
        self.assertEqual(
            sorted(
                getattr(RESULTS, n)
                for n in dir(RESULTS)
                if not n.startswith("_")
            ),
            ["failed", "passed"],
        )

    def test_non_enum_category_is_forced_to_unknown(self):
        """Free text must never reach the closed category field."""
        report = VerificationReport()
        report.add_finding(
            VerificationFinding(
                category="some future category",
                stage=STAGES.UNKNOWN,
                message="x",
            )
        )
        self.assertEqual(report.findings[0].category, CATEGORIES.UNKNOWN)

    def test_unclassifiable_exception_becomes_unknown(self):
        """Unknown exceptions map to the unknown category and are kept."""
        report = VerificationReport()
        report.record_failure(STAGES.UNKNOWN, RuntimeError("boom"))
        data = report.to_dict()
        self.assertEqual(data["result"], RESULTS.FAILED)
        self.assertEqual(data["findings"][0]["category"], CATEGORIES.UNKNOWN)
        self.assertEqual(
            data["findings"][0]["detail"]["error_type"], "RuntimeError"
        )
        self.assertIn("boom", data["findings"][0]["message"])

    def test_passing_report_is_homogeneous_and_empty(self):
        """Passing verification uses the same schema with no findings."""
        report = VerificationReport()
        data = report.to_dict()
        self.assertEqual(data["result"], RESULTS.PASSED)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["summary"]["finding_count"], 0)
        self.assertFalse(data["summary"]["truncated"])
        # JSON serializable and re-parseable.
        json.loads(report.to_json())

    def test_findings_are_sorted_deterministically(self):
        """Report ordering does not depend on insertion order."""
        report = VerificationReport()
        for stage in [STAGES.STEP_RULES, STAGES.LINK_LOADING]:
            report.add_finding(
                VerificationFinding(
                    category=CATEGORIES.RULE_FAILURE,
                    stage=stage,
                    message="m",
                )
            )
        report2 = VerificationReport()
        for stage in [STAGES.LINK_LOADING, STAGES.STEP_RULES]:
            report2.add_finding(
                VerificationFinding(
                    category=CATEGORIES.RULE_FAILURE,
                    stage=stage,
                    message="m",
                )
            )
        self.assertEqual(report.to_json(), report2.to_json())

    def test_truncation_is_marked(self):
        """Findings beyond the cap are dropped and clearly marked."""
        report = VerificationReport(max_findings=2)
        for i in range(5):
            report.add_finding(
                VerificationFinding(
                    category=CATEGORIES.UNKNOWN,
                    stage=STAGES.UNKNOWN,
                    message=f"f{i}",
                )
            )
        data = report.to_dict()
        self.assertTrue(data["summary"]["truncated"])
        self.assertEqual(data["summary"]["finding_count"], 2)
        self.assertEqual(data["summary"]["max_findings"], 2)

    def test_default_cap_is_documentated_constant(self):
        self.assertEqual(MAX_FINDINGS, 1000)

    def test_sets_are_serialized_as_sorted_lists(self):
        finding = VerificationFinding(
            category=CATEGORIES.RULE_FAILURE,
            stage=STAGES.STEP_RULES,
            message="m",
            actual={"paths": {"b", "a"}},
        )
        self.assertEqual(finding.to_dict()["actual"]["paths"], ["a", "b"])

    def test_report_error_chain_preserved(self):
        report = VerificationReport()
        try:
            try:
                raise ValueError("inner")
            except ValueError as inner:
                raise RuntimeError("outer") from inner
        except RuntimeError as exc:
            report.record_failure(STAGES.UNKNOWN, exc)

        chain = report.to_dict()["findings"][0]["detail"]["error_chain"]
        self.assertEqual(
            [e["error_type"] for e in chain], ["RuntimeError", "ValueError"]
        )

    def test_degradation_on_attribution_failure(self):
        """record_report_error stores the minimal stage conclusion."""
        report = VerificationReport()
        report.record_report_error(STAGES.STEP_RULES, RuntimeError("kaboom"))
        self.assertEqual(
            report.to_dict()["report_errors"][0]["stage"], "step_rules"
        )

    def test_add_finding_rejects_wrong_type(self):
        report = VerificationReport()
        with self.assertRaises(TypeError):
            report.add_finding("not a finding")

    def test_unrepresentable_value_does_not_crash(self):
        """A value whose str() raises still produces a usable report."""

        class Broken:
            def __str__(self):
                raise RuntimeError("cannot stringify")

        finding = VerificationFinding(
            category=CATEGORIES.UNKNOWN,
            stage=STAGES.UNKNOWN,
            message=Broken(),
            actual={"weird": Broken()},
        )
        raw = finding.to_dict()
        self.assertIn("unrepresentable", raw["message"])
        self.assertIn("unrepresentable", raw["actual"]["weird"])

    def test_json_safe_falls_back_for_unknown_types(self):
        finding = VerificationFinding(
            category=CATEGORIES.UNKNOWN,
            stage=STAGES.UNKNOWN,
            message="m",
            actual=object(),
        )
        self.assertIsInstance(finding.to_dict()["actual"], str)

    def test_merge_sublayout_prefixes_and_propagates_state(self):
        parent = VerificationReport()
        sub = VerificationReport()
        sub.add_finding(
            VerificationFinding(
                category=CATEGORIES.RULE_FAILURE,
                stage=STAGES.STEP_RULES,
                message="inner",
                item_name="inner-step",
            )
        )
        sub.record_report_error(STAGES.STEP_RULES, RuntimeError("x"))
        parent.merge_sublayout("outer", sub)
        data = parent.to_dict()
        self.assertEqual(data["result"], RESULTS.FAILED)
        self.assertEqual(data["findings"][0]["item_path"], "outer")
        self.assertEqual(
            data["findings"][0]["detail"]["sublayout_root"], "outer"
        )
        self.assertEqual(data["report_errors"][0]["stage"], STAGES.SUBLAYOUT)

    def test_merge_sublayout_depth_limit(self):
        report = VerificationReport()
        sub = VerificationReport()
        report.merge_sublayout("outer", sub, depth=999)
        self.assertTrue(report.to_dict()["report_errors"])

    def test_join_path_with_and_without_suffix(self):
        self.assertEqual(_join_path("outer", ""), "outer")
        self.assertEqual(_join_path("outer", "inner"), "outer.inner")


class TestVerifyWithReport(unittest.TestCase, TmpDirMixin):
    """Integration tests for verifylib report production."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.alice = SignerStore.rsa
        cls.alice_pub = SignerStore.rsa_pub
        cls.bob = SignerStore.ecdsa
        cls.bob_pub = SignerStore.ecdsa_pub

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        # Each test gets an isolated subdirectory under the class temp dir.
        self.case_dir = os.path.realpath(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.case_dir, ignore_errors=True)

    def _run(self, metadata, key_dict=None):
        key_dict = key_dict or {self.alice_pub["keyid"]: self.alice_pub}
        return in_toto_verify_with_report(metadata, key_dict)

    def test_passing_verification_report(self):
        """A passing run yields a homogeneous empty report and a summary link."""
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[Step(name="build", pubkeys=[self.alice_pub["keyid"]])],
        )
        link = _make_link(
            "build", self.alice, products={"foo": {"sha256": "a" * 64}}
        )
        with _Chdir(self.case_dir):
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            summary, report = self._run(Metablock.from_dict(layout.to_dict()))
        data = report.to_dict()
        self.assertEqual(data["result"], RESULTS.PASSED)
        self.assertEqual(data["findings"], [])
        self.assertIsNotNone(summary)

    def test_rule_and_threshold_failures_co_occur(self):
        """Acceptance: rule failure and threshold failure both listed."""
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                    threshold=2,
                    expected_products=[["DISALLOW", "*"]],
                )
            ],
        )
        link = _make_link(
            "build", self.alice, products={"foo": {"sha256": "a" * 64}}
        )
        with _Chdir(self.case_dir):
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            _, report = self._run(Metablock.from_dict(layout.to_dict()))

        data = report.to_dict()
        categories = {f["category"] for f in data["findings"]}
        self.assertIn(CATEGORIES.RULE_FAILURE, categories)
        self.assertIn(CATEGORIES.SIGNATURE_THRESHOLD, categories)
        self.assertIn(CATEGORIES.MATERIAL_MISSING, categories)

        rule_finding = next(
            f
            for f in data["findings"]
            if f["category"] == CATEGORIES.RULE_FAILURE
        )
        # Rule position and remaining queue after the rule.
        self.assertEqual(rule_finding["rule_index"], 0)
        self.assertEqual(rule_finding["rule_type"], "disallow")
        self.assertEqual(rule_finding["artifact_type"], "products")
        self.assertEqual(
            rule_finding["detail"]["remaining_artifacts_after_rule"], ["foo"]
        )
        # Expected and actual are directly comparable.
        self.assertEqual(rule_finding["expected"]["matched_artifacts"], [])
        self.assertEqual(rule_finding["actual"]["matched_artifacts"], ["foo"])

        threshold_finding = next(
            f
            for f in data["findings"]
            if f["stage"] == STAGES.LINK_SIGNATURE_THRESHOLDS
        )
        self.assertEqual(threshold_finding["expected"]["valid_signer_count"], 2)
        self.assertEqual(threshold_finding["actual"]["valid_signer_count"], 1)
        self.assertEqual(
            threshold_finding["detail"]["missing_signer_keyids"],
            [self.bob_pub["keyid"]],
        )

    def test_repeated_runs_are_identical(self):
        """Acceptance: order and content stable across repeated verification."""
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                    threshold=2,
                    expected_products=[["DISALLOW", "*"]],
                )
            ],
        )
        link = _make_link(
            "build", self.alice, products={"foo": {"sha256": "a" * 64}}
        )
        with _Chdir(self.case_dir):
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            reports = []
            for _ in range(3):
                _, report = self._run(Metablock.from_dict(layout.to_dict()))
                reports.append(report.to_json())
        self.assertEqual(len(set(reports)), 1)

    def test_no_sensitive_data_in_report(self):
        """Acceptance: no key material, hashes or file contents leak."""
        sensitive_contents = "TOP-SECRET-FILE-CONTENT"
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                    threshold=2,
                    expected_products=[["DISALLOW", "*"]],
                )
            ],
        )
        link = _make_link(
            "build",
            self.alice,
            products={"secret.txt": {"sha256": "f" * 64}},
        )
        with _Chdir(self.case_dir):
            with open("secret.txt", "w", encoding="utf8") as fp:
                fp.write(sensitive_contents)
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            _, report = self._run(Metablock.from_dict(layout.to_dict()))
            raw = report.to_json()

        self.assertNotIn(sensitive_contents, raw)
        # No hash digests, no PEM key material.
        self.assertNotIn("f" * 64, raw)
        self.assertNotIn("-----BEGIN", raw)
        self.assertNotIn("PRIVATE KEY", raw)
        # Artifact *paths* are allowed and required for attribution.
        self.assertIn("secret.txt", raw)

    def test_truncation_in_integration(self):
        """Acceptance: cap truncates findings and flags it."""
        # 10 steps each missing its only link -> at least 10 material findings,
        # capped at 3.
        steps = [
            Step(name=f"step-{i}", pubkeys=[self.alice_pub["keyid"]])
            for i in range(10)
        ]
        layout = _make_layout(self.alice, self.alice_pub, steps=steps)
        with (
            _Chdir(self.case_dir),
            patch.object(in_toto.reportlib, "MAX_FINDINGS", 3),
        ):
            _, report = in_toto_verify_with_report(
                Metablock.from_dict(layout.to_dict()),
                {self.alice_pub["keyid"]: self.alice_pub},
            )
        data = report.to_dict()
        self.assertTrue(data["summary"]["truncated"])
        self.assertLessEqual(data["summary"]["finding_count"], 3)

    def test_legacy_mode_still_raises_at_original_points(self):
        """Backward compatibility: exceptions unchanged in type and timing."""
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[Step(name="build", pubkeys=[self.alice_pub["keyid"]])],
        )
        with (
            _Chdir(self.case_dir),
            self.assertRaises(LinkNotFoundError),
        ):
            in_toto_verify(
                Metablock.from_dict(layout.to_dict()),
                {self.alice_pub["keyid"]: self.alice_pub},
            )

    def test_legacy_rule_exception_unchanged(self):
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"]],
                    expected_products=[["DISALLOW", "*"]],
                )
            ],
        )
        link = _make_link(
            "build", self.alice, products={"foo": {"sha256": "a" * 64}}
        )
        with _Chdir(self.case_dir):
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            with self.assertRaises(RuleVerificationError) as ctx:
                in_toto_verify(
                    Metablock.from_dict(layout.to_dict()),
                    {self.alice_pub["keyid"]: self.alice_pub},
                )
        self.assertIn("DISALLOW *", str(ctx.exception))

    def test_command_return_value_failure(self):
        """Bad inspection return values are categorized and non-fatal in
        report mode."""
        scripts_directory = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "scripts"
        )
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            inspect=[
                Inspection(
                    name="failer",
                    run=[
                        VersionedPython,
                        os.path.join(scripts_directory, "expr"),
                        "1",
                        "/",
                        "0",
                    ],
                )
            ],
        )
        with _Chdir(self.case_dir):
            # Legacy mode still raises.
            with self.assertRaises(BadReturnValueError):
                in_toto_verify(
                    Metablock.from_dict(layout.to_dict()),
                    {self.alice_pub["keyid"]: self.alice_pub},
                    persist_inspection_links=False,
                )

            _, report = in_toto_verify_with_report(
                Metablock.from_dict(layout.to_dict()),
                {self.alice_pub["keyid"]: self.alice_pub},
                persist_inspection_links=False,
            )
        data = report.to_dict()
        finding = next(
            f
            for f in data["findings"]
            if f["category"] == CATEGORIES.COMMAND_RETURN_VALUE
        )
        self.assertEqual(finding["item_type"], ITEM_TYPES.INSPECTION)
        self.assertEqual(finding["item_name"], "failer")
        self.assertEqual(finding["expected"]["return_value"], 0)
        self.assertNotEqual(finding["actual"]["return_value"], 0)

    def test_require_rule_failure_lists_expected_and_actual(self):
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"]],
                    expected_materials=[["REQUIRE", "missing.txt"]],
                )
            ],
        )
        link = _make_link("build", self.alice)
        with _Chdir(self.case_dir):
            link.dump(
                FILENAME_FORMAT.format(
                    step_name="build", keyid=self.alice_pub["keyid"]
                )
            )
            _, report = self._run(Metablock.from_dict(layout.to_dict()))
        finding = report.to_dict()["findings"][0]
        self.assertEqual(finding["rule_type"], "require")
        self.assertEqual(finding["expected"]["present"], True)
        self.assertEqual(finding["actual"]["present"], False)
        self.assertEqual(finding["actual"]["required_artifact"], "missing.txt")

    def test_bad_layout_signature_is_attributed_and_terminal(self):
        """Layout signature failures stop verification with a report."""
        layout = _make_layout(self.alice, self.alice_pub)
        # Tamper after signing to break the signature.
        layout.signed.readme = "tampered"
        _, report = in_toto_verify_with_report(
            layout, {self.alice_pub["keyid"]: self.alice_pub}
        )
        data = report.to_dict()
        self.assertEqual(data["result"], RESULTS.FAILED)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["stage"], "layout_signatures")

    def test_expired_layout_is_attributed(self):
        expired = Layout(keys={self.alice_pub["keyid"]: self.alice_pub})
        expired.expires = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        layout = Metablock(signed=expired)
        layout.create_signature(self.alice)
        _, report = in_toto_verify_with_report(
            layout, {self.alice_pub["keyid"]: self.alice_pub}
        )
        stages = {f["stage"] for f in report.to_dict()["findings"]}
        self.assertIn("layout_expiration", stages)

    def test_parameter_substitution_failure_is_attributed(self):
        layout = _make_layout(self.alice, self.alice_pub)
        _, report = in_toto_verify_with_report(
            layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            substitution_parameters={},
        )
        # The empty layout has no placeholders, so force a real failure via
        # a rule referencing an unknown parameter.
        layout2 = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"]],
                    expected_products=[["CREATE", "{missing}"]],
                )
            ],
        )
        _, report2 = in_toto_verify_with_report(
            layout2,
            {self.alice_pub["keyid"]: self.alice_pub},
            substitution_parameters={},
        )
        stages = {f["stage"] for f in report2.to_dict()["findings"]}
        self.assertIn("parameter_substitution", stages)
        # First call still produced a well-formed report.
        self.assertIn("result", report.to_dict())

    def test_threshold_artifact_mismatch_is_attributed(self):
        """Two functionaries with threshold 2 but differing artifacts."""
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                    threshold=2,
                )
            ]
        )
        link_a = Link(name="build", materials={"foo": {"sha256": "a" * 64}})
        link_b = Link(name="build", materials={"foo": {"sha256": "b" * 64}})
        chain = {
            "build": {
                self.alice_pub["keyid"]: link_a,
                self.bob_pub["keyid"]: link_b,
            }
        }
        report = VerificationReport()
        token = verifylib._ACTIVE_REPORT.set(report)
        try:
            verify_threshold_constraints(layout, chain)
        finally:
            verifylib._ACTIVE_REPORT.reset(token)

        finding = report.to_dict()["findings"][0]
        self.assertEqual(finding["category"], CATEGORIES.SIGNATURE_THRESHOLD)
        self.assertEqual(finding["detail"]["reason"], "artifact_mismatch")

    def test_attribution_safety_net_records_unknown_stage(self):
        """An unexpected internal error degrades to a minimal report."""
        layout = _make_layout(self.alice, self.alice_pub)
        with patch(
            "in_toto.verifylib.verify_metadata_signatures",
            side_effect=RuntimeError("unexpected internal boom"),
        ):
            _, report = in_toto_verify_with_report(
                layout, {self.alice_pub["keyid"]: self.alice_pub}
            )
        data = report.to_dict()
        self.assertEqual(data["result"], RESULTS.FAILED)
        self.assertEqual(data["findings"][0]["category"], CATEGORIES.UNKNOWN)
        self.assertEqual(
            data["findings"][0]["detail"]["error_type"], "RuntimeError"
        )

    def test_missing_step_summary_does_not_crash(self):
        """A layout whose every step lacks links still returns a report."""
        layout = _make_layout(
            self.alice,
            self.alice_pub,
            steps=[Step(name="ghost", pubkeys=[self.alice_pub["keyid"]])],
        )
        summary, report = in_toto_verify_with_report(
            layout, {self.alice_pub["keyid"]: self.alice_pub}
        )
        self.assertIsNotNone(summary)
        self.assertTrue(report.to_dict()["findings"])

    def test_record_finding_failure_degrades_to_report_error(self):
        """If recording a finding raises, a report error is stored instead."""
        report = VerificationReport()
        token = verifylib._ACTIVE_REPORT.set(report)
        try:
            with patch.object(
                report, "add_finding", side_effect=RuntimeError("recorder down")
            ):
                verifylib._record_finding(
                    VerificationFinding(
                        category=CATEGORIES.UNKNOWN,
                        stage=STAGES.STEP_RULES,
                        message="x",
                    )
                )
        finally:
            verifylib._ACTIVE_REPORT.reset(token)
        self.assertEqual(
            report.to_dict()["report_errors"][0]["stage"], "step_rules"
        )

    def test_legacy_rule_evaluation_without_link_raises_keyerror(self):
        """Legacy mode keeps the original KeyError for a missing item link."""
        with self.assertRaises(KeyError):
            verify_item_rules(
                "missing-item",
                ARTIFACT_TYPES.MATERIALS,
                [],
                {},
                item_type=ITEM_TYPES.STEP,
            )


class TestSublayoutReport(unittest.TestCase, TmpDirMixin):
    """Inner failures carry the outer step's full path."""

    def test_sublayout_failure_path_prefix(self):
        self.set_up_test_dir()
        try:
            demo_files = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "demo_files"
            )
            for fn in os.listdir(demo_files):
                shutil.copy(os.path.join(demo_files, fn), ".")

            alice = SignerStore.rsa
            alice_pub = SignerStore.rsa_pub
            sub_layout_name = "sub_layout"
            sub_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
                name=sub_layout_name, keyid=alice_pub["keyid"]
            )
            for name in glob.glob("*.link"):
                os.renames(name, os.path.join(sub_link_dir, name))

            sub_layout = Metablock.load("demo.layout.template")
            # Break the inner layout's step rule to force an inner failure.
            sub_layout.signed.steps[0].expected_products.insert(
                0, ["DISALLOW", "*"]
            )
            sub_layout.create_signature(alice)
            sub_layout.dump(
                FILENAME_FORMAT.format(
                    step_name=sub_layout_name, keyid=alice_pub["keyid"]
                )
            )

            super_layout = Layout()
            super_layout.keys[alice_pub["keyid"]] = alice_pub
            super_layout.steps.append(
                Step(name=sub_layout_name, pubkeys=[alice_pub["keyid"]])
            )
            super_meta = Metablock(signed=super_layout)
            super_meta.create_signature(alice)

            _, report = in_toto_verify_with_report(
                super_meta, {alice_pub["keyid"]: alice_pub}
            )
            data = report.to_dict()
            self.assertTrue(data["findings"])
            # Every inner finding must carry the outer step's path as prefix.
            self.assertTrue(
                all(
                    f["item_path"] == sub_layout_name
                    or f["item_path"].startswith(f"{sub_layout_name}.")
                    for f in data["findings"]
                ),
                data["findings"],
            )
            inner_rule_finding = next(
                f
                for f in data["findings"]
                if f["category"] == CATEGORIES.RULE_FAILURE
            )
            self.assertEqual(inner_rule_finding["item_path"], sub_layout_name)
            self.assertEqual(
                inner_rule_finding["detail"]["sublayout_root"],
                sub_layout_name,
            )
        finally:
            self.tear_down_test_dir()


class TestRulelibStandaloneTraceback(unittest.TestCase):
    """The pre-existing RULE_TRACE KeyError regression stays fixed."""

    def test_disallow_standalone_does_not_keyerror(self):
        with self.assertRaises(RuleVerificationError):
            verify_disallow_rule("*", {"foo"})
        with self.assertRaises(RuleVerificationError):
            verify_require_rule("foo", {"bar"})


class _Chdir:
    """Small context manager to chdir for the duration of a block."""

    def __init__(self, path):
        self.path = path
        self.previous = None

    def __enter__(self):
        self.previous = os.getcwd()
        os.chdir(self.path)
        return self

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self.previous)
