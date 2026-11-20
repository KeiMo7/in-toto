# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_verify_report.py

<Purpose>
  Tests for report-driven, multi-step supply chain verification:

  - every step gets an independent conclusion, even if an earlier step fails
  - missing metadata, insufficient signers and rule violations are attributed
    to the step that caused them
  - signer counts name satisfied and missing distinct signers
  - a master key and its subkeys count as one signer
  - step order is derived from artifact dependencies, not layout order
  - reference cycles and dangling references are rejected up front
  - nested sublayout failures carry the complete outer step path
  - contradicting artifact lists name the conflicting entries
  - passing verification yields a per-step summary
  - repeated verification is deterministic
"""

import json
import os
import unittest
from unittest.mock import patch

import attr
import securesystemslib._gpg.functions
from securesystemslib._gpg.constants import have_gpg

from in_toto.exceptions import LayoutReferenceError
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT, Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verify_report import (
    CATEGORY_INCONSISTENT_ARTIFACTS,
    CATEGORY_INSUFFICIENT_SIGNERS,
    CATEGORY_METADATA_MISSING,
    CATEGORY_METADATA_UNPARSEABLE,
    CATEGORY_RULE_EVALUATION_ERROR,
    CATEGORY_RULE_VIOLATION,
    STATUS_FAILED,
    STATUS_PASSED,
    STATUS_UNDETERMINED,
    VerificationReport,
)
from in_toto.verifylib import (
    in_toto_verify,
    verify_layout_report,
    verify_threshold_constraints,
)
from tests.common import GPGKeysMixin, SignerStore, TmpDirMixin

DEMO_FILES = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "demo_files"
)
SCRIPTS = os.path.join(os.path.dirname(os.path.realpath(__file__)), "scripts")

SHA_FOO = "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
SHA_BAR = "155c693a6b7481f48626ebfc545f05236df679f0099225d6d0bc472e6dd21155"


def _write_link(step_name, keyid, signer, materials=None, products=None):
    """Create and sign a link file for a step and dump it to the cwd."""
    link = Metablock(
        signed=Link(
            name=step_name,
            materials=materials or {},
            products=products or {},
        )
    )
    link.create_signature(signer)
    link.dump(FILENAME_FORMAT.format(step_name=step_name, keyid=keyid))


def _write_raw_link(step_name, keyid, contents):
    """Write arbitrary bytes to a link filename."""
    with open(
        FILENAME_FORMAT.format(step_name=step_name, keyid=keyid),
        "w",
        encoding="utf8",
    ) as handle:
        handle.write(contents)


def _signed_layout(layout, signer=SignerStore.rsa):
    """Return a signed Metablock for the layout, signed with the given signer."""
    metadata = Metablock(signed=layout)
    metadata.create_signature(signer)
    return metadata


class ReportTestBase(unittest.TestCase, TmpDirMixin):
    """Base class with the demo keys and a temp working directory per test."""

    def setUp(self):
        self.set_up_test_dir()
        self.alice = SignerStore.rsa
        self.alice_pub = SignerStore.rsa_pub
        self.alice_keyid = self.alice_pub["keyid"]
        self.bob = SignerStore.ecdsa
        self.bob_pub = SignerStore.ecdsa_pub
        self.bob_keyid = self.bob_pub["keyid"]
        self.carl = SignerStore.ed25519
        self.carl_pub = SignerStore.ed25519_pub
        self.carl_keyid = self.carl_pub["keyid"]
        self.keys = {
            self.alice_keyid: self.alice_pub,
            self.bob_keyid: self.bob_pub,
            self.carl_keyid: self.carl_pub,
        }

    def tearDown(self):
        self.tear_down_test_dir()

    def layout_metadata(self, layout, signer=None):
        return _signed_layout(layout or Layout(), signer or self.alice)

    def run_report(self, layout, layout_key_dict=None):
        return verify_layout_report(
            self.layout_metadata(layout),
            layout_key_dict or {self.alice_keyid: self.alice_pub},
        )


class TestEveryStepGetsAConclusion(ReportTestBase):
    """A failing step must not prevent later steps from getting a result."""

    def test_three_step_chain_only_middle_product_rule_fails(self):
        """Three chained steps, only the middle step's product rule fails."""
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[self.alice_keyid],
                    expected_products=[["CREATE", "foo"]],
                ),
                Step(
                    name="package",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write-code",
                        ]
                    ],
                    expected_products=[
                        ["CREATE", "foo.tar.gz"],
                        ["DISALLOW", "*"],
                    ],
                ),
                Step(
                    name="publish",
                    pubkeys=[self.carl_keyid],
                    expected_materials=[
                        [
                            "MATCH",
                            "foo.tar.gz",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "package",
                        ]
                    ],
                    expected_products=[["ALLOW", "*"]],
                ),
            ],
        )

        _write_link(
            "write-code",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "package",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
            products={
                "foo.tar.gz": {"sha256": SHA_BAR},
                "leftover.o": {"sha256": SHA_FOO},
            },
        )
        _write_link(
            "publish",
            self.carl_keyid,
            self.carl,
            materials={"foo.tar.gz": {"sha256": SHA_BAR}},
            products={"published": {"sha256": SHA_FOO}},
        )

        report = self.run_report(layout)

        self.assertEqual(len(report.steps), 3)
        by_name = {item.name: item for item in report.steps}
        # All three steps have a conclusion, and all three were evaluated.
        for name in ("write-code", "package", "publish"):
            self.assertIn(name, by_name)
            self.assertNotEqual(by_name[name].status, STATUS_UNDETERMINED)

        self.assertEqual(by_name["write-code"].status, STATUS_PASSED)
        self.assertEqual(by_name["package"].status, STATUS_FAILED)
        self.assertEqual(by_name["publish"].status, STATUS_PASSED)

        # The failure is attributed to "package" and to its product rule.
        package_issues = by_name["package"].issues
        self.assertTrue(
            any(
                issue.category == CATEGORY_RULE_VIOLATION
                and issue.details["source_type"] == "products"
                and issue.path == ("package",)
                for issue in package_issues
            )
        )
        self.assertEqual(report.verdict, STATUS_FAILED)

    def test_pass_report_has_step_summary(self):
        """A passing verification yields one summary entry per step."""
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[self.alice_keyid],
                    expected_products=[["CREATE", "foo"]],
                ),
                Step(
                    name="package",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write-code",
                        ]
                    ],
                    expected_products=[["CREATE", "foo.tar.gz"]],
                ),
            ],
        )
        _write_link(
            "write-code",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "package",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
            products={"foo.tar.gz": {"sha256": SHA_BAR}},
        )

        report = self.run_report(layout)
        self.assertEqual(report.verdict, STATUS_PASSED)
        self.assertEqual(
            [item.name for item in report.steps], ["write-code", "package"]
        )
        for item in report.steps:
            self.assertEqual(item.status, STATUS_PASSED)
            self.assertEqual(item.threshold, 1)
            self.assertEqual(item.satisfied_signers, 1)
            self.assertEqual(item.missing_signers, 0)

        summary = report.format()
        self.assertIn("verification: passed", summary)
        self.assertIn("step 'write-code': passed", summary)
        self.assertIn("step 'package': passed", summary)


class TestThreeCauseAttribution(ReportTestBase):
    """Missing metadata, insufficient signers and rule violations are distinct."""

    def test_all_three_causes_attributed_to_their_step(self):
        layout = Layout(
            keys=self.keys,
            steps=[
                # Nobody produced metadata for this step.
                Step(name="missing-metadata", pubkeys=[self.alice_keyid]),
                # Two functionaries are required, only one is present.
                Step(
                    name="under-threshold",
                    pubkeys=[self.alice_keyid, self.bob_keyid],
                    threshold=2,
                ),
                # Link is present, but the product rule does not hold.
                Step(
                    name="rule-fails",
                    pubkeys=[self.carl_keyid],
                    expected_products=[
                        ["CREATE", "expected-artifact"],
                        ["DISALLOW", "*"],
                    ],
                ),
            ],
        )

        _write_link("under-threshold", self.alice_keyid, self.alice)
        _write_link(
            "rule-fails",
            self.carl_keyid,
            self.carl,
            products={"unexpected": {"sha256": SHA_FOO}},
        )

        report = self.run_report(layout)
        by_name = {item.name: item for item in report.steps}

        missing_categories = {
            issue.category for issue in by_name["missing-metadata"].issues
        }
        self.assertIn(CATEGORY_METADATA_MISSING, missing_categories)
        self.assertEqual(
            by_name["missing-metadata"].status, STATUS_UNDETERMINED
        )

        threshold_categories = {
            issue.category for issue in by_name["under-threshold"].issues
        }
        self.assertIn(CATEGORY_INSUFFICIENT_SIGNERS, threshold_categories)
        self.assertEqual(by_name["under-threshold"].status, STATUS_FAILED)

        rule_categories = {
            issue.category for issue in by_name["rule-fails"].issues
        }
        self.assertIn(CATEGORY_RULE_VIOLATION, rule_categories)
        self.assertEqual(by_name["rule-fails"].status, STATUS_FAILED)

        # Every issue names the step it belongs to.
        self.assertEqual(
            {
                issue.step
                for issue in report.iter_issues()
                if issue.category
                in {
                    CATEGORY_METADATA_MISSING,
                    CATEGORY_INSUFFICIENT_SIGNERS,
                    CATEGORY_RULE_VIOLATION,
                }
            },
            {"missing-metadata", "under-threshold", "rule-fails"},
        )

    def test_unparseable_metadata_is_skipped_and_attributed(self):
        """A corrupt metadata file fails only its own step."""
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(name="broken", pubkeys=[self.alice_keyid]),
                Step(name="healthy", pubkeys=[self.bob_keyid]),
            ],
        )
        _write_raw_link("broken", self.alice_keyid, "{ not json")
        _write_link("healthy", self.bob_keyid, self.bob)

        report = self.run_report(layout)
        by_name = {item.name: item for item in report.steps}

        # Requirement: unparseable metadata is skipped and is a failure of
        # the step it belongs to.
        self.assertEqual(by_name["broken"].status, STATUS_FAILED)
        self.assertTrue(
            any(
                issue.category == CATEGORY_METADATA_UNPARSEABLE
                for issue in by_name["broken"].issues
            )
        )
        self.assertEqual(by_name["healthy"].status, STATUS_PASSED)


class TestSignerCounting(ReportTestBase):
    """Thresholds count distinct signers, not keys or files."""

    def test_missing_signer_counts_are_readable(self):
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="needs-three",
                    pubkeys=[self.alice_keyid, self.bob_keyid, self.carl_keyid],
                    threshold=3,
                )
            ],
        )
        _write_link("needs-three", self.alice_keyid, self.alice)
        _write_link("needs-three", self.bob_keyid, self.bob)

        report = self.run_report(layout)
        item = report.steps[0]
        self.assertEqual(item.threshold, 3)
        self.assertEqual(item.satisfied_signers, 2)
        self.assertEqual(item.missing_signers, 1)
        self.assertEqual(item.status, STATUS_FAILED)

        issue = next(
            issue
            for issue in item.issues
            if issue.category == CATEGORY_INSUFFICIENT_SIGNERS
        )
        self.assertEqual(issue.details["satisfied_signers"], 2)
        self.assertEqual(issue.details["missing_signers"], 1)
        self.assertEqual(issue.details["required_signers"], 3)
        self.assertIn("missing signers: '1'", issue.message)
        self.assertIn("Satisfied signers: '2'", issue.message)


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestMasterAndSubkeyCountOnce(
    unittest.TestCase, TmpDirMixin, GPGKeysMixin
):
    """A link signed by a master key and one signed by its subkey count once."""

    def setUp(self):
        self.set_up_test_dir()
        self.set_up_gpg_keys()

        masterkey = "40e692c3ae03f6b88dff95d0d2c9fe930766998d"
        subkey1 = "35830aa342b9fea0178876b02b25647ff0ef59fe"
        subkey2 = "732d722578f71a9ec967a64bfead922c91eb7351"

        self.masterkey = masterkey
        self.subkey1 = subkey1
        self.subkey2 = subkey2

        self.key_bundle = securesystemslib._gpg.functions.export_pubkey(
            masterkey, self.gnupg_home
        )

    def tearDown(self):
        self.tear_down_test_dir()

    def _signed_link(self, name):
        return Metablock(signed=Link(name=name))

    def _dump_link(self, link, step_name, keyid):
        link.dump(FILENAME_FORMAT.format(step_name=step_name, keyid=keyid))

    def test_two_subkeys_of_same_master_count_as_one_signer(self):
        step_name = "step"
        link1 = self._signed_link(step_name)
        link1.sign_gpg(self.subkey1, self.gnupg_home)
        link2 = self._signed_link(step_name)
        link2.sign_gpg(self.subkey2, self.gnupg_home)

        # Two links, each from a different subkey of the same master key.
        self._dump_link(link1, step_name, self.subkey1)
        self._dump_link(link2, step_name, self.subkey2)

        layout = Layout(
            steps=[Step(name=step_name, pubkeys=[self.masterkey], threshold=2)],
            keys={self.masterkey: self.key_bundle},
        )

        report = verify_layout_report(
            _signed_layout(layout),
            {self.masterkey: self.key_bundle},
        )
        item = report.steps[0]
        self.assertEqual(item.satisfied_signers, 1)
        self.assertEqual(item.missing_signers, 1)
        self.assertEqual(item.status, STATUS_FAILED)
        self.assertIn(
            CATEGORY_INSUFFICIENT_SIGNERS,
            {issue.category for issue in item.issues},
        )

        # The count is also reflected in metadata naming.
        self.assertEqual(item.signer_keyids, (self.masterkey,))

    def test_master_and_subkey_signatures_count_as_one_signer(self):
        step_name = "step"
        link1 = self._signed_link(step_name)
        link1.sign_gpg(self.masterkey, self.gnupg_home)
        link2 = self._signed_link(step_name)
        link2.sign_gpg(self.subkey1, self.gnupg_home)

        # GPG signs with the signing subkey either way; both links carry the
        # same signing keyid and must count as a single signer.
        self._dump_link(link1, step_name, self.subkey1)

        layout = Layout(
            steps=[Step(name=step_name, pubkeys=[self.masterkey], threshold=2)],
            keys={self.masterkey: self.key_bundle},
        )

        report = verify_layout_report(
            _signed_layout(layout),
            {self.masterkey: self.key_bundle},
        )
        item = report.steps[0]
        # GPG signs with the signing subkey either way, so the two links are
        # the *same* key signing twice; they must still count as one signer.
        self.assertEqual(item.satisfied_signers, 1)
        self.assertEqual(item.status, STATUS_FAILED)


class TestDependencyOrder(ReportTestBase):
    """Step order comes from artifact references, not layout order."""

    def _layout(self, steps):
        return Layout(keys=self.keys, steps=steps)

    def _write_chain_links(self):
        _write_link(
            "write-code",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "package",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
            products={"foo.tar.gz": {"sha256": SHA_BAR}},
        )
        _write_link(
            "publish",
            self.carl_keyid,
            self.carl,
            materials={"foo.tar.gz": {"sha256": SHA_BAR}},
            products={"published": {"sha256": SHA_FOO}},
        )

    def _steps(self):
        return [
            Step(
                name="write-code",
                pubkeys=[self.alice_keyid],
                expected_products=[["CREATE", "foo"]],
            ),
            Step(
                name="package",
                pubkeys=[self.bob_keyid],
                expected_materials=[
                    ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "write-code"]
                ],
                expected_products=[["CREATE", "foo.tar.gz"]],
            ),
            Step(
                name="publish",
                pubkeys=[self.carl_keyid],
                expected_materials=[
                    [
                        "MATCH",
                        "foo.tar.gz",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "package",
                    ]
                ],
                expected_products=[["ALLOW", "*"]],
            ),
        ]

    def test_layout_order_does_not_change_conclusions(self):
        self._write_chain_links()
        forward = self._layout(self._steps())
        backward = self._layout(list(reversed(self._steps())))

        report_forward = self.run_report(forward)
        report_backward = self.run_report(backward)

        self.assertEqual(
            report_forward.ordered_step_names,
            ["write-code", "package", "publish"],
        )
        self.assertEqual(
            report_backward.ordered_step_names,
            report_forward.ordered_step_names,
        )
        # Verdicts, counts and summary agree despite the different layout order.
        self.assertEqual(
            report_forward.to_dict()["steps"],
            report_backward.to_dict()["steps"],
        )
        self.assertEqual(
            [item.name for item in report_forward.steps],
            ["write-code", "package", "publish"],
        )

    def test_cycle_is_rejected_before_verification(self):
        layout = self._layout(
            [
                Step(
                    name="first",
                    pubkeys=[self.alice_keyid],
                    expected_products=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "second"]
                    ],
                ),
                Step(
                    name="second",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "first"]
                    ],
                ),
            ]
        )
        with self.assertRaises(LayoutReferenceError) as context:
            self.run_report(layout)

        error = context.exception
        self.assertIsNotNone(error.cycle)
        self.assertEqual(error.cycle[0], error.cycle[-1])
        self.assertIn("first", error.cycle)
        self.assertIn("second", error.cycle)
        self.assertIn("cycle", str(error))

    def test_dangling_reference_is_rejected_before_verification(self):
        layout = self._layout(
            [
                Step(
                    name="lonely",
                    pubkeys=[self.alice_keyid],
                    expected_products=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "nowhere"]
                    ],
                )
            ]
        )
        with self.assertRaises(LayoutReferenceError) as context:
            self.run_report(layout)

        error = context.exception
        self.assertEqual(error.step, "lonely")
        self.assertEqual(error.reference, "nowhere")
        self.assertIn("nowhere", str(error))

    def test_default_verification_still_raises_on_cycle(self):
        """The historical API rejects cycles with a FormatError subclass."""
        from in_toto.exceptions import LinkNotFoundError  # noqa: PLC0415
        from in_toto.verifylib import in_toto_verify  # noqa: PLC0415

        layout = self._layout(
            [
                Step(
                    name="first",
                    pubkeys=[self.alice_keyid],
                    expected_products=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "second"]
                    ],
                ),
                Step(
                    name="second",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "first"]
                    ],
                ),
            ]
        )
        with self.assertRaises(LayoutReferenceError):
            in_toto_verify(
                self.layout_metadata(layout), {self.alice_keyid: self.alice_pub}
            )
        self.assertTrue(issubclass(LayoutReferenceError, Exception))
        self.assertFalse(issubclass(LayoutReferenceError, LinkNotFoundError))


class TestNestedSublayoutAttribution(ReportTestBase):
    """Inner failures carry the complete outer step path."""

    def test_nested_failure_path_includes_outer_step(self):
        # Root layout delegates to a sublayout in step "delegated".
        sublayout_step_name = "inner-failing"
        root_step_name = "delegated"

        sublayout = Layout(
            keys={self.carl_keyid: self.carl_pub},
            steps=[
                Step(
                    name=sublayout_step_name,
                    pubkeys=[self.carl_keyid],
                    expected_products=[
                        ["CREATE", "expected-artifact"],
                        ["DISALLOW", "*"],
                    ],
                )
            ],
        )
        sub_metadata = Metablock(signed=sublayout)
        sub_metadata.create_signature(self.bob)

        # The sublayout is stored as the link of the root step.
        sub_metadata.dump(
            FILENAME_FORMAT.format(
                step_name=root_step_name, keyid=self.bob_keyid
            )
        )
        sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=root_step_name, keyid=self.bob_keyid
        )
        os.mkdir(sub_dir)

        # The inner step's link lives in the sublayout's namespaced directory.
        inner_link = Metablock(
            signed=Link(
                name=sublayout_step_name,
                products={"unexpected": {"sha256": SHA_FOO}},
            )
        )
        inner_link.create_signature(self.carl)
        inner_link.dump(
            os.path.join(
                sub_dir,
                FILENAME_FORMAT.format(
                    step_name=sublayout_step_name, keyid=self.carl_keyid
                ),
            )
        )

        root_layout = Layout(
            keys={self.bob_keyid: self.bob_pub},
            steps=[Step(name=root_step_name, pubkeys=[self.bob_keyid])],
        )

        report = self.run_report(root_layout)
        issues = list(report.iter_issues())

        nested_issues = [
            issue
            for issue in issues
            if issue.category == CATEGORY_RULE_VIOLATION
        ]
        self.assertEqual(len(nested_issues), 1)
        self.assertEqual(
            nested_issues[0].path, (root_step_name, sublayout_step_name)
        )
        self.assertIn(
            f"{root_step_name}/{sublayout_step_name}", report.format()
        )


class TestInconsistentArtifacts(ReportTestBase):
    """Contradicting artifact lists of a step name the conflicting entries."""

    def test_contradicting_links_name_conflict_entries(self):
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="dual",
                    pubkeys=[self.alice_keyid, self.bob_keyid],
                    threshold=2,
                )
            ],
        )
        _write_link(
            "dual",
            self.alice_keyid,
            self.alice,
            materials={"foo": {"sha256": SHA_FOO}},
            products={"bar": {"sha256": SHA_BAR}},
        )
        _write_link(
            "dual",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_BAR}},
            products={"bar": {"sha256": SHA_BAR}, "baz": {"sha256": SHA_FOO}},
        )

        report = self.run_report(layout)
        item = report.steps[0]
        self.assertEqual(item.status, STATUS_FAILED)

        issue = next(
            issue
            for issue in item.issues
            if issue.category == CATEGORY_INCONSISTENT_ARTIFACTS
        )
        self.assertEqual(sorted(issue.details["materials"]), ["foo"])
        self.assertEqual(sorted(issue.details["products"]), ["baz"])
        self.assertIn("materials:foo", issue.message)
        self.assertIn("products:baz", issue.message)
        self.assertIn("hash mismatch", issue.message)
        self.assertIn("only in conflicting link", issue.message)

    def test_direct_call_still_raises(self):
        """Without a report, the historical exception is preserved."""
        from in_toto.exceptions import ThresholdVerificationError  # noqa: PLC0415

        layout = Layout(steps=[Step(name="dual", threshold=2)])
        link_alice = Link(name="dual", materials={"foo": {"sha256": SHA_FOO}})
        link_bob = Link(name="dual", materials={"foo": {"sha256": SHA_BAR}})
        chain_link_dict = {
            "dual": {self.alice_keyid: link_alice, self.bob_keyid: link_bob}
        }
        with self.assertRaises(ThresholdVerificationError):
            verify_threshold_constraints(layout, chain_link_dict)


class TestNestedLayoutLevelFailures(ReportTestBase):
    """Failures inside delegated layouts keep the outer step path."""

    ROOT_STEP = "delegated"
    INNER_STEP = "inner"

    def _write_sublayout(self, sublayout, signer, dump_inner=None):
        sub_metadata = Metablock(signed=sublayout)
        sub_metadata.create_signature(signer)
        sub_metadata.dump(
            FILENAME_FORMAT.format(
                step_name=self.ROOT_STEP, keyid=self.bob_keyid
            )
        )
        sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=self.ROOT_STEP, keyid=self.bob_keyid
        )
        os.mkdir(sub_dir)
        if dump_inner is not None:
            dump_inner(sub_dir)
        return sub_dir

    def _root_layout(self):
        return Layout(
            keys={self.bob_keyid: self.bob_pub},
            steps=[Step(name=self.ROOT_STEP, pubkeys=[self.bob_keyid])],
        )

    def test_missing_inner_metadata_is_undetermined_with_full_path(self):
        sublayout = Layout(
            keys={self.carl_keyid: self.carl_pub},
            steps=[Step(name=self.INNER_STEP, pubkeys=[self.carl_keyid])],
        )
        self._write_sublayout(sublayout, self.bob)

        report = self.run_report(self._root_layout())
        root_item = report.steps[0]
        self.assertEqual(root_item.name, self.ROOT_STEP)

        nested = root_item.sub_reports[0]
        self.assertEqual(nested.path, (self.ROOT_STEP, self.INNER_STEP))
        self.assertEqual(nested.status, STATUS_UNDETERMINED)
        self.assertTrue(
            any(
                issue.category == CATEGORY_METADATA_MISSING
                for issue in nested.issues
            )
        )
        # Undetermined is not a pass.
        self.assertEqual(report.verdict, STATUS_UNDETERMINED)

    def test_cycle_inside_sublayout_is_rejected_up_front(self):
        sublayout = Layout(
            steps=[
                Step(
                    name="a",
                    pubkeys=[self.carl_keyid],
                    expected_products=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "b"]
                    ],
                ),
                Step(
                    name="b",
                    pubkeys=[self.carl_keyid],
                    expected_materials=[
                        ["MATCH", "x", "WITH", "PRODUCTS", "FROM", "a"]
                    ],
                ),
            ]
        )
        self._write_sublayout(sublayout, self.bob)
        with self.assertRaises(LayoutReferenceError) as context:
            self.run_report(self._root_layout())
        self.assertIn("a", context.exception.cycle)
        self.assertIn("b", context.exception.cycle)

    def test_bad_sublayout_signature_is_attributed_and_does_not_crash(self):
        sublayout = Layout(
            keys={self.carl_keyid: self.carl_pub},
            steps=[Step(name=self.INNER_STEP, pubkeys=[self.carl_keyid])],
        )
        # Root layout lists bob as functionary, but carl signs the sublayout.
        self._write_sublayout(sublayout, self.carl)

        report = self.run_report(self._root_layout())
        item = report.steps[0]
        self.assertEqual(item.status, STATUS_FAILED)
        self.assertTrue(
            any(
                issue.category == CATEGORY_INSUFFICIENT_SIGNERS
                for issue in item.issues
            )
        )


class TestLayoutLevelFindings(ReportTestBase):
    """Layout signature and expiration failures are reported, not raised."""

    def test_expired_layout_is_a_report_issue(self):
        layout = Layout(keys=self.keys, steps=[])
        layout.expires = "2000-01-01T00:00:00Z"
        report = self.run_report(layout)
        self.assertEqual(report.verdict, STATUS_FAILED)
        self.assertTrue(
            any(
                issue.category == "layout_expired"
                for issue in report.iter_issues()
            )
        )

    def test_bad_layout_signature_is_a_report_issue(self):
        metadata = _signed_layout(Layout(keys=self.keys, steps=[]))
        # Pass a key that did not sign the layout.
        report = verify_layout_report(metadata, {self.bob_keyid: self.bob_pub})
        self.assertEqual(report.verdict, STATUS_FAILED)
        self.assertTrue(
            any(
                issue.category == "layout_signature"
                for issue in report.iter_issues()
            )
        )


class TestUntrustedUpstreamEvidence(ReportTestBase):
    """A step may not pass on evidence from an unauthenticated step."""

    def test_downstream_step_is_undetermined_when_upstream_is_untrusted(self):
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="upstream",
                    pubkeys=[self.alice_keyid],
                    expected_products=[["CREATE", "foo"]],
                ),
                Step(
                    name="downstream",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "upstream",
                        ]
                    ],
                    expected_products=[["ALLOW", "*"]],
                ),
            ],
        )
        # The upstream link file is named for the authorized keyid, but is
        # signed by an unauthorized key: its evidence cannot be trusted. The
        # downstream link itself is perfectly valid.
        _write_link(
            "upstream",
            self.alice_keyid,
            self.carl,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "downstream",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
        )

        report = self.run_report(layout)
        by_name = {item.name: item for item in report.steps}

        self.assertEqual(by_name["upstream"].status, STATUS_FAILED)
        # Downstream has valid evidence of its own, but must not be declared a
        # pass when the artifacts it matched against are untrusted.
        self.assertEqual(by_name["downstream"].status, STATUS_UNDETERMINED)
        self.assertTrue(
            any(
                issue.category == CATEGORY_RULE_EVALUATION_ERROR
                and "upstream" in issue.message
                for issue in by_name["downstream"].issues
            )
        )
        self.assertEqual(report.verdict, STATUS_FAILED)

    def test_downstream_passes_when_upstream_is_trusted_but_rule_fails(self):
        """A rule violation upstream still allows trustworthy artifact data."""
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="upstream",
                    pubkeys=[self.alice_keyid],
                    # The rule fails, but the evidence is authentic.
                    expected_products=[
                        ["CREATE", "expected"],
                        ["DISALLOW", "foo"],
                    ],
                ),
                Step(
                    name="downstream",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        [
                            "MATCH",
                            "foo",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "upstream",
                        ]
                    ],
                    expected_products=[["ALLOW", "*"]],
                ),
            ],
        )
        _write_link(
            "upstream",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "downstream",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
        )

        report = self.run_report(layout)
        by_name = {item.name: item for item in report.steps}
        self.assertEqual(by_name["upstream"].status, STATUS_FAILED)
        self.assertEqual(by_name["downstream"].status, STATUS_PASSED)
        self.assertEqual(report.verdict, STATUS_FAILED)


class TestInterruptedVerification(ReportTestBase):
    """An interrupted verification keeps completed results readable."""

    def test_unexpected_failure_leaves_partial_report_undetermined(self):
        layout = Layout(
            keys=self.keys,
            steps=[
                Step(name="first", pubkeys=[self.alice_keyid]),
                Step(name="second", pubkeys=[self.bob_keyid]),
            ],
        )
        _write_link("first", self.alice_keyid, self.alice)
        _write_link("second", self.bob_keyid, self.bob)

        report = VerificationReport()
        with (
            patch(
                "in_toto.verifylib.verify_threshold_constraints",
                side_effect=RuntimeError("boom"),
            ),
            self.assertRaises(RuntimeError),
        ):
            in_toto_verify(
                self.layout_metadata(layout),
                {self.alice_keyid: self.alice_pub},
                report=report,
            )

        # The already-completed steps remain readable ...
        self.assertEqual(
            [item.name for item in report.steps], ["first", "second"]
        )
        self.assertEqual(
            [item.satisfied_signers for item in report.steps], [1, 1]
        )
        # ... and the interrupted verification is not reported as a pass.
        self.assertFalse(report.complete)
        self.assertEqual(report.verdict, STATUS_UNDETERMINED)


class TestDeterminismAndCompatibility(ReportTestBase):
    """Repeated verification is byte-identical; legacy semantics are intact."""

    def _layout(self):
        return Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="alpha",
                    pubkeys=[self.alice_keyid],
                    expected_products=[["CREATE", "foo"]],
                ),
                Step(
                    name="beta",
                    pubkeys=[self.bob_keyid],
                    expected_materials=[
                        ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "alpha"]
                    ],
                    expected_products=[["CREATE", "bar"]],
                ),
            ],
        )

    def _write_links(self):
        _write_link(
            "alpha",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        _write_link(
            "beta",
            self.bob_keyid,
            self.bob,
            materials={"foo": {"sha256": SHA_FOO}},
            products={"bar": {"sha256": SHA_BAR}},
        )

    def test_repeated_verification_is_identical(self):
        self._write_links()
        first = self.run_report(self._layout())
        second = self.run_report(self._layout())

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.format(), second.format())
        self.assertEqual(
            json.dumps(first.to_dict(), sort_keys=True),
            json.dumps(second.to_dict(), sort_keys=True),
        )

    def test_legacy_summary_link_unchanged(self):
        """The default API still returns the same summary link semantics."""
        from in_toto.verifylib import in_toto_verify  # noqa: PLC0415

        self._write_links()
        metadata = self.layout_metadata(self._layout())
        legacy = in_toto_verify(metadata, {self.alice_keyid: self.alice_pub})

        report = self.run_report(self._layout())
        self.assertEqual(report.verdict, STATUS_PASSED)
        self.assertEqual(attr.asdict(report.summary_link), attr.asdict(legacy))
        self.assertEqual(report.summary_link.materials, legacy.materials)
        self.assertEqual(report.summary_link.products, legacy.products)
        self.assertEqual(report.summary_link.byproducts, legacy.byproducts)

    def test_default_api_still_raises_rule_error(self):
        """Default verification keeps raising the historical exception type."""
        from in_toto.exceptions import RuleVerificationError  # noqa: PLC0415
        from in_toto.verifylib import in_toto_verify  # noqa: PLC0415

        layout = Layout(
            keys=self.keys,
            steps=[
                Step(
                    name="alpha",
                    pubkeys=[self.alice_keyid],
                    expected_products=[["DISALLOW", "*"]],
                )
            ],
        )
        _write_link(
            "alpha",
            self.alice_keyid,
            self.alice,
            products={"foo": {"sha256": SHA_FOO}},
        )
        with self.assertRaises(RuleVerificationError):
            in_toto_verify(
                self.layout_metadata(layout), {self.alice_keyid: self.alice_pub}
            )
