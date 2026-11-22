# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_proofchain.py

<Purpose>
  Test breakpoint diagnosis and opt-in partial verification for provenance
  proof chains.

"""

import copy
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from in_toto import proofchain
from in_toto.exceptions import ProofStoreTimeout, ProofStoreUnavailable
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.proofchain import (
    ChainVerdict,
    Confidence,
    LayerStatus,
    ProofLocation,
    ProofStore,
    diagnose_provenance_chain,
)
from in_toto.verifylib import in_toto_verify
from tests.common import SignerStore, TmpDirMixin

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_TAMPERED = "d" * 64


def _hash(digest):
    return {"sha256": digest}


class _FakeStore(ProofStore):
    """In-memory proof store with configurable per-layer behavior."""

    def __init__(self, proofs=None, errors=None):
        self.proofs = proofs or {}
        self.errors = errors or {}
        self.name = "fake proof store"

    def fetch(self, layer_id, proof_type):
        error = self.errors.get(layer_id)
        if error is not None:
            raise error
        return self.proofs.get(layer_id)


class ProvenanceFixture(TmpDirMixin, unittest.TestCase):
    """Shared three-layer chain: vendor library -> image -> application."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        cls.alice = SignerStore.rsa
        cls.alice_pub = SignerStore.rsa_pub
        cls.bob = SignerStore.ecdsa
        cls.bob_pub = SignerStore.ecdsa_pub
        cls.carl = SignerStore.ed25519
        cls.carl_pub = SignerStore.ed25519_pub

        cls.keys = {
            cls.alice_pub["keyid"]: cls.alice_pub,
            cls.bob_pub["keyid"]: cls.bob_pub,
            cls.carl_pub["keyid"]: cls.carl_pub,
        }
        cls.signers = {
            "lib": cls.alice,
            "image": cls.bob,
            "app": cls.carl,
        }
        cls.pubkeys = {
            "lib": cls.alice_pub,
            "image": cls.bob_pub,
            "app": cls.carl_pub,
        }

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        self.link_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.layout = self._make_layout()
        self.links = self._make_links()

    def tearDown(self):
        if os.path.isdir(self.link_dir):
            shutil.rmtree(self.link_dir)

    def _make_layout(self, materialize=True):
        steps = [
            Step(name="lib", pubkeys=[self.alice_pub["keyid"]]),
            Step(name="image", pubkeys=[self.bob_pub["keyid"]]),
            Step(name="app", pubkeys=[self.carl_pub["keyid"]]),
        ]
        layout = Metablock(signed=Layout(steps=steps, keys=self.keys))
        if materialize:
            layout.create_signature(self.alice)
        return layout

    def _make_links(self):
        return {
            "lib": Link(
                name="lib",
                materials={"vendor.tar": _hash(SHA_A)},
                products={"lib.so": _hash(SHA_B)},
            ),
            "image": Link(
                name="image",
                materials={"lib.so": _hash(SHA_B)},
                products={"image.tar": _hash(SHA_C)},
            ),
            "app": Link(
                name="app",
                materials={"image.tar": _hash(SHA_C)},
                products={"app.bin": _hash(SHA_A)},
            ),
        }

    def layer_path(self, name):
        return os.path.join(
            self.link_dir,
            FILENAME_FORMAT.format(
                step_name=name, keyid=self.pubkeys[name]["keyid"]
            ),
        )

    def dump_link(self, name, link, signer=None, path=None):
        metadata = Metablock(signed=copy.deepcopy(link))
        metadata.create_signature(signer or self.signers[name])
        metadata.dump(path or self.layer_path(name))
        return metadata

    def write_all(self):
        for name, link in self.links.items():
            self.dump_link(name, link)

    def diagnose(self, **kwargs):
        kwargs.setdefault("link_dir_path", self.link_dir)
        return diagnose_provenance_chain(
            self.layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            **kwargs,
        )


class TestCompleteChain(ProvenanceFixture):
    """A complete, consistent three-layer chain verifies fully."""

    def test_complete_chain(self):
        self.write_all()

        diagnosis = self.diagnose()

        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)
        self.assertIs(diagnosis.confidence, Confidence.FULL)
        self.assertTrue(diagnosis.is_acceptable())
        self.assertIsNone(diagnosis.first_break)
        self.assertEqual(diagnosis.verified_layers, ["lib", "image", "app"])
        self.assertEqual(diagnosis.failed_layers, [])

        for layer in diagnosis.layers:
            self.assertIs(layer.status, LayerStatus.VERIFIED)
            self.assertEqual(layer.expected_proof_type, "link")
            self.assertTrue(layer.continuity_verified)
            self.assertIn("link", layer.expected_proof_files[0])

        self.assertIsNotNone(diagnosis.summary_link)
        self.assertEqual(
            diagnosis.summary_link.materials, self.links["lib"].materials
        )
        self.assertEqual(
            diagnosis.summary_link.products, self.links["app"].products
        )

    def test_regular_verification_agrees(self):
        """Diagnosis verdict matches the regular verification result."""
        self.write_all()

        # Regular verification must pass and diagnosis must agree.
        in_toto_verify(
            self.layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )
        self.assertIs(self.diagnose().verdict, ChainVerdict.VERIFIED)

    def test_report_render_and_json(self):
        self.write_all()
        diagnosis = self.diagnose()

        rendered = diagnosis.render()
        self.assertIn("VERIFIED", rendered)
        self.assertIn("Breakpoint: none", rendered)

        payload = json.loads(diagnosis.to_json())
        self.assertEqual(payload["verdict"], "verified")
        self.assertEqual(payload["confidence"], "full")
        self.assertEqual(payload["verified_layers"], ["lib", "image", "app"])
        self.assertTrue(payload["acceptable"])


class TestMissingLayer(ProvenanceFixture):
    """A missing layer pinpoints the break without changing verification."""

    def test_missing_middle_layer(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        diagnosis = self.diagnose()

        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertIs(diagnosis.confidence, Confidence.REDUCED)
        self.assertFalse(diagnosis.is_acceptable())

        self.assertEqual(diagnosis.verified_layers, ["lib", "app"])
        self.assertEqual(
            [layer.layer_id for layer in diagnosis.layers],
            ["lib", "image", "app"],
        )
        missing = diagnosis.layers[1]
        self.assertIs(missing.status, LayerStatus.MISSING_NOT_BUNDLED)
        self.assertEqual(missing.expected_proof_type, "link")
        self.assertIn(
            f"image.{self.bob_pub['keyid'][:8]}.link",
            missing.expected_proof_files,
        )

        # The third layer is still reported, but explicitly isolated.
        third = diagnosis.layers[2]
        self.assertIs(third.status, LayerStatus.VERIFIED)
        self.assertFalse(third.continuity_verified)

        # The breakpoint names the layer and the expected proof type.
        self.assertIsNotNone(diagnosis.first_break)
        self.assertEqual(diagnosis.first_break.layer_id, "image")
        self.assertEqual(diagnosis.first_break.index, 1)
        self.assertEqual(diagnosis.first_break.expected_proof_type, "link")
        self.assertIn("not shipped", diagnosis.first_break.reason.lower())

    def test_regular_verification_still_rejects(self):
        """Diagnosis never turns regular verification into a pass."""
        self.write_all()
        os.remove(self.layer_path("image"))

        diagnosis = self.diagnose(tolerant=True)
        self.assertEqual(diagnosis.verified_layers, ["lib", "app"])

        with self.assertRaises(Exception):
            in_toto_verify(
                self.layout,
                {self.alice_pub["keyid"]: self.alice_pub},
                link_dir_path=self.link_dir,
            )

    def test_tolerant_mode_accepts_only_partial(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        self.assertFalse(self.diagnose().is_acceptable())
        tolerant = self.diagnose(tolerant=True)
        self.assertTrue(tolerant.is_acceptable())
        self.assertIs(tolerant.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertIs(tolerant.confidence, Confidence.REDUCED)

    def test_missing_first_layer(self):
        self.write_all()
        os.remove(self.layer_path("lib"))

        diagnosis = self.diagnose()
        self.assertEqual(diagnosis.first_break.layer_id, "lib")
        self.assertEqual(diagnosis.first_break.index, 0)
        # Later layers still exist and are verified, but isolated.
        self.assertEqual(diagnosis.verified_layers, ["image", "app"])
        self.assertFalse(diagnosis.layers[1].continuity_verified)


class TestUnverifiableProof(ProvenanceFixture):
    """An unknown format is unverifiable, not a verification failure."""

    def test_unknown_container_format(self):
        self.write_all()
        with open(self.layer_path("image"), "w", encoding="utf8") as fp:
            json.dump({"something": "unknown"}, fp)

        diagnosis = self.diagnose()

        self.assertIs(diagnosis.verdict, ChainVerdict.UNVERIFIABLE)
        self.assertIs(diagnosis.confidence, Confidence.NONE)
        self.assertFalse(diagnosis.is_acceptable())
        layer = diagnosis.layers[1]
        self.assertIs(layer.status, LayerStatus.UNVERIFIABLE)
        self.assertIn("unrecognized", layer.reason)
        # Explicitly distinct from missing and invalid.
        self.assertEqual(diagnosis.failed_layers, [])

    def test_too_new_format_version_asks_for_upgrade(self):
        self.write_all()
        metadata = Metablock(signed=copy.deepcopy(self.links["image"]))
        metadata.create_signature(self.bob)
        document = metadata.to_dict()
        document["provenanceFormatVersion"] = 99
        with open(self.layer_path("image"), "w", encoding="utf8") as fp:
            json.dump(document, fp)

        diagnosis = self.diagnose()
        layer = diagnosis.layers[1]

        self.assertIs(layer.status, LayerStatus.UNVERIFIABLE)
        self.assertIn("needs an upgrade", layer.reason)
        self.assertIn("Upgrade", layer.remediation)
        self.assertEqual(layer.format_version, 99)
        self.assertIs(diagnosis.verdict, ChainVerdict.UNVERIFIABLE)

    def test_supported_format_version_is_verified(self):
        self.write_all()
        metadata = Metablock(signed=copy.deepcopy(self.links["image"]))
        metadata.create_signature(self.bob)
        document = metadata.to_dict()
        document["_provenance"] = {"formatVersion": 1}
        with open(self.layer_path("image"), "w", encoding="utf8") as fp:
            json.dump(document, fp)

        diagnosis = self.diagnose()
        self.assertIs(diagnosis.layers[1].status, LayerStatus.VERIFIED)
        self.assertEqual(diagnosis.layers[1].format_version, 1)

    def test_non_json_proof_is_unverifiable(self):
        self.write_all()
        with open(self.layer_path("image"), "w", encoding="utf8") as fp:
            fp.write("{ this is not json")

        layer = self.diagnose().layers[1]
        self.assertIs(layer.status, LayerStatus.UNVERIFIABLE)
        self.assertIn("not valid JSON", layer.reason)


class TestTamperedContent(ProvenanceFixture):
    """Valid signatures over replaced content are detected as tampering."""

    def test_artifact_content_mismatch(self):
        self.write_all()

        # Create the real artifact the last layer claims to have produced.
        with open(
            os.path.join(self.link_dir, "app.bin"), "w", encoding="utf8"
        ) as fp:
            fp.write("the real app")

        diagnosis = self.diagnose(artifact_base_path=self.link_dir)
        layer = diagnosis.layers[2]

        self.assertIs(layer.status, LayerStatus.TAMPERED)
        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)
        self.assertFalse(diagnosis.is_acceptable())
        self.assertEqual(diagnosis.failed_layers, ["app"])
        self.assertEqual(layer.tamper_details[0]["path"], "app.bin")
        self.assertEqual(layer.tamper_details[0]["kind"], "artifact")

    def test_cross_layer_mismatch(self):
        """A signed link whose materials do not match the previous products."""
        self.write_all()

        forged = Link(
            name="image",
            materials={"lib.so": _hash(SHA_TAMPERED)},
            products={"image.tar": _hash(SHA_C)},
        )
        # Signature is valid: the functionary really signed this statement.
        self.dump_link("image", forged)

        diagnosis = self.diagnose()
        layer = diagnosis.layers[1]

        self.assertIs(layer.status, LayerStatus.TAMPERED)
        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)
        self.assertEqual(layer.tamper_details[0]["kind"], "cross_layer")
        self.assertEqual(layer.tamper_details[0]["path"], "lib.so")

    def test_tampered_is_not_missing_or_unverifiable(self):
        self.write_all()
        forged = Link(
            name="image",
            materials={"lib.so": _hash(SHA_TAMPERED)},
            products={"image.tar": _hash(SHA_C)},
        )
        self.dump_link("image", forged)

        diagnosis = self.diagnose()
        statuses = {layer.status for layer in diagnosis.layers}
        self.assertIn(LayerStatus.TAMPERED, statuses)
        self.assertNotIn(LayerStatus.MISSING_NOT_BUNDLED, statuses)
        self.assertNotIn(LayerStatus.UNVERIFIABLE, statuses)


class TestSignatureSemantics(ProvenanceFixture):
    """Multi-signature missing/absent vs broken semantics are fixed."""

    def _threshold_path(self, keyid):
        return os.path.join(
            self.link_dir,
            FILENAME_FORMAT.format(step_name="lib", keyid=keyid),
        )

    def _threshold_layout(self, threshold=2):
        steps = [
            Step(
                name="lib",
                pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                threshold=threshold,
            )
        ]
        layout = Metablock(
            signed=Layout(
                steps=steps,
                keys={
                    self.alice_pub["keyid"]: self.alice_pub,
                    self.bob_pub["keyid"]: self.bob_pub,
                },
            )
        )
        layout.create_signature(self.alice)
        return layout

    def test_missing_cosignature_is_pending(self):
        layout = self._threshold_layout()
        metadata = Metablock(signed=copy.deepcopy(self.links["lib"]))
        metadata.create_signature(self.alice)
        metadata.dump(self._threshold_path(self.alice_pub["keyid"]))

        # The per-functionary filename only matches Alice; Bob's is absent.
        diagnosis = diagnose_provenance_chain(
            layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )
        layer = diagnosis.layers[0]

        self.assertIs(layer.status, LayerStatus.PENDING_SIGNATURES)
        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertFalse(diagnosis.is_acceptable())
        self.assertIn("pending, not invalid", layer.reason)

    def test_pending_is_never_acceptable_without_tolerance(self):
        # Two layers: 'lib' verifies, 'image' is pending a co-signature.
        steps = [
            Step(name="lib", pubkeys=[self.alice_pub["keyid"]]),
            Step(
                name="image",
                pubkeys=[self.bob_pub["keyid"], self.carl_pub["keyid"]],
                threshold=2,
            ),
        ]
        layout = Metablock(
            signed=Layout(
                steps=steps,
                keys={
                    self.alice_pub["keyid"]: self.alice_pub,
                    self.bob_pub["keyid"]: self.bob_pub,
                    self.carl_pub["keyid"]: self.carl_pub,
                },
            )
        )
        layout.create_signature(self.alice)

        self.dump_link("lib", self.links["lib"])
        partial = Metablock(signed=copy.deepcopy(self.links["image"]))
        partial.create_signature(self.bob)
        partial.dump(self.layer_path("image"))

        pending = diagnose_provenance_chain(layout, link_dir_path=self.link_dir)
        self.assertIs(pending.layers[1].status, LayerStatus.PENDING_SIGNATURES)
        self.assertIs(pending.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertFalse(pending.is_acceptable())

        tolerant = diagnose_provenance_chain(
            layout, link_dir_path=self.link_dir, tolerant=True
        )
        self.assertTrue(tolerant.is_acceptable())

    def test_pending_alone_is_not_acceptable_even_when_tolerant(self):
        """Tolerant mode needs at least one verified layer to accept."""
        layout = self._threshold_layout()
        metadata = Metablock(signed=copy.deepcopy(self.links["lib"]))
        metadata.create_signature(self.alice)
        metadata.dump(self._threshold_path(self.alice_pub["keyid"]))

        tolerant = diagnose_provenance_chain(
            layout, link_dir_path=self.link_dir, tolerant=True
        )
        self.assertIs(tolerant.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertFalse(tolerant.is_acceptable())

    def test_multi_signed_single_proof_verifies(self):
        layout = self._threshold_layout()
        metadata = Metablock(signed=copy.deepcopy(self.links["lib"]))
        metadata.create_signature(self.alice)
        metadata.create_signature(self.bob)
        metadata.dump(self._threshold_path(self.alice_pub["keyid"]))

        diagnosis = diagnose_provenance_chain(
            layout, link_dir_path=self.link_dir
        )
        self.assertIs(diagnosis.layers[0].status, LayerStatus.VERIFIED)
        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)

    def test_broken_signature_is_invalid_not_pending(self):
        layout = self._threshold_layout()
        metadata = Metablock(signed=copy.deepcopy(self.links["lib"]))
        metadata.create_signature(self.alice)
        metadata.create_signature(self.bob)
        # Signature present but the content changed afterwards.
        metadata.signed.products = {"lib.so": _hash(SHA_TAMPERED)}
        metadata.dump(self._threshold_path(self.alice_pub["keyid"]))

        diagnosis = diagnose_provenance_chain(
            layout, link_dir_path=self.link_dir
        )
        layer = diagnosis.layers[0]
        self.assertIs(layer.status, LayerStatus.INVALID_SIGNATURE)
        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)
        self.assertFalse(diagnosis.is_acceptable())
        self.assertTrue(diagnosis.tolerant is False)


class TestProofStorage(ProvenanceFixture):
    """Bundled vs store storage changes what 'missing' means."""

    def test_bundled_missing_means_not_shipped(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        layer = self.diagnose(
            proof_locations={"image": ProofLocation.BUNDLED}
        ).layers[1]
        self.assertIs(layer.status, LayerStatus.MISSING_NOT_BUNDLED)
        self.assertIn("not shipped", layer.missing_meaning)
        self.assertIn("packaging", layer.missing_meaning)

    def test_store_missing_means_maybe_deleted(self):
        self.write_all()
        store = _FakeStore(proofs={})

        diagnosis = self.diagnose(
            proof_locations={"image": ProofLocation.STORE},
            proof_store=store,
        )
        layer = diagnosis.layers[1]
        self.assertIs(layer.status, LayerStatus.MISSING_FROM_STORE)
        self.assertIn("deletion", layer.missing_meaning)
        self.assertFalse(layer.retryable)

    def test_store_proof_is_used(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        metadata = Metablock(signed=copy.deepcopy(self.links["image"]))
        metadata.create_signature(self.bob)
        store = _FakeStore(proofs={"image": metadata.to_dict()})

        diagnosis = self.diagnose(proof_store=store)
        self.assertIs(diagnosis.layers[1].status, LayerStatus.VERIFIED)
        self.assertEqual(diagnosis.layers[1].location, "store")

    def test_store_unreachable_is_unavailable_not_invalid(self):
        self.write_all()
        os.remove(self.layer_path("image"))
        store = _FakeStore(
            errors={"image": ProofStoreUnavailable("connection refused")}
        )

        diagnosis = self.diagnose(proof_store=store)
        layer = diagnosis.layers[1]

        self.assertIs(layer.status, LayerStatus.UNAVAILABLE)
        self.assertNotIn(layer.status, proofchain._FAILED_STATUSES)
        self.assertTrue(layer.retryable)
        self.assertIn("retry", layer.remediation.lower())
        self.assertIn("not as an invalid proof", layer.remediation)
        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)

    def test_store_timeout_marks_partial(self):
        self.write_all()
        os.remove(self.layer_path("image"))
        store = _FakeStore(errors={"image": ProofStoreTimeout("timed out")})

        diagnosis = self.diagnose(proof_store=store)

        self.assertIs(diagnosis.layers[1].status, LayerStatus.TIMEOUT)
        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertIs(diagnosis.confidence, Confidence.REDUCED)
        self.assertTrue(diagnosis.layers[1].retryable)
        self.assertIn("timed out", diagnosis.layers[1].reason.lower())

    def test_file_store_reachable_and_missing(self):
        store_dir = tempfile.mkdtemp(dir=os.getcwd())
        try:
            self.write_all()
            os.remove(self.layer_path("image"))

            diagnosis = self.diagnose(
                proof_store=proofchain.FileProofStore(store_dir)
            )
            self.assertIs(
                diagnosis.layers[1].status, LayerStatus.MISSING_FROM_STORE
            )
        finally:
            shutil.rmtree(store_dir)

    def test_file_store_directory_absent_is_unavailable(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        diagnosis = self.diagnose(
            proof_store=proofchain.FileProofStore(
                os.path.join(self.link_dir, "does-not-exist")
            )
        )
        self.assertIs(diagnosis.layers[1].status, LayerStatus.UNAVAILABLE)
        self.assertTrue(diagnosis.layers[1].retryable)


class TestRootLayout(ProvenanceFixture):
    """Root layout problems are not mistaken for layer problems."""

    def test_bad_root_signature(self):
        self.write_all()
        wrong_key = {self.bob_pub["keyid"]: self.bob_pub}

        diagnosis = diagnose_provenance_chain(
            self.layout, wrong_key, link_dir_path=self.link_dir
        )

        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)
        self.assertIn("Root layout signature", diagnosis.root_error)
        self.assertFalse(diagnosis.is_acceptable())

    def test_expired_root(self):
        layout = copy.deepcopy(self.layout)
        layout.signed.expires = "2000-01-01T00:00:00Z"
        layout.signatures = []
        layout.create_signature(self.alice)
        self.write_all()

        diagnosis = diagnose_provenance_chain(
            layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )
        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)
        self.assertIn("expired", diagnosis.root_error)


class TestMultiLevelSublayout(ProvenanceFixture):
    """Diagnosis recurses into delegated layouts and reports nested breaks."""

    def _build_sublayout_chain(self):
        # Root layout delegates to a sublayout signed by Alice.
        sub_step = Step(
            name="delegated",
            pubkeys=[self.alice_pub["keyid"]],
        )
        root = Metablock(
            signed=Layout(
                steps=[sub_step],
                keys={
                    self.alice_pub["keyid"]: self.alice_pub,
                },
            )
        )
        root.create_signature(self.alice)

        sub_link = Link(
            name="sub-step",
            materials={"src": _hash(SHA_A)},
            products={"out": _hash(SHA_B)},
        )
        sub_layout = Metablock(
            signed=Layout(
                steps=[Step(name="sub-step", pubkeys=[self.bob_pub["keyid"]])],
                keys={self.bob_pub["keyid"]: self.bob_pub},
            )
        )
        sub_layout.create_signature(self.alice)
        sub_layout.dump(
            os.path.join(
                self.link_dir,
                FILENAME_FORMAT.format(
                    step_name="delegated", keyid=self.alice_pub["keyid"]
                ),
            )
        )

        sub_dir = os.path.join(
            self.link_dir,
            proofchain.SUBLAYOUT_LINK_DIR_FORMAT.format(
                name="delegated", keyid=self.alice_pub["keyid"]
            ),
        )
        os.mkdir(sub_dir)
        metadata = Metablock(signed=sub_link)
        metadata.create_signature(self.bob)
        metadata.dump(
            os.path.join(
                sub_dir,
                FILENAME_FORMAT.format(
                    step_name="sub-step", keyid=self.bob_pub["keyid"]
                ),
            )
        )
        return root, sub_dir

    def test_nested_chain_verifies(self):
        root, _ = self._build_sublayout_chain()
        diagnosis = diagnose_provenance_chain(
            root,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )

        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)
        layer = diagnosis.layers[0]
        self.assertIs(layer.status, LayerStatus.VERIFIED)
        self.assertEqual(layer.expected_proof_type, "layout")
        self.assertIsNotNone(layer.nested)
        self.assertIs(layer.nested.verdict, ChainVerdict.VERIFIED)

    def test_nested_break_is_surfaced(self):
        root, sub_dir = self._build_sublayout_chain()
        os.remove(
            os.path.join(
                sub_dir,
                FILENAME_FORMAT.format(
                    step_name="sub-step", keyid=self.bob_pub["keyid"]
                ),
            )
        )

        diagnosis = diagnose_provenance_chain(
            root,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )
        layer = diagnosis.layers[0]

        self.assertIs(layer.status, LayerStatus.MISSING_NOT_BUNDLED)
        self.assertIsNotNone(layer.nested)
        self.assertEqual(layer.nested.first_break.layer_id, "sub-step")
        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertFalse(diagnosis.is_acceptable())


class TestRealSupplyChainFixture(ProvenanceFixture):
    """Three-tier 'vendor library -> image -> application' comparison.

    This fixture asserts that full diagnosis and regular verification agree,
    and that breakpoint diagnosis reports the same conclusion for a chain with
    a missing proof.
    """

    def test_full_chain_agreement(self):
        self.write_all()

        in_toto_verify(
            self.layout,
            {self.alice_pub["keyid"]: self.alice_pub},
            link_dir_path=self.link_dir,
        )
        diagnosis = self.diagnose()

        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)
        self.assertEqual(diagnosis.verified_layers, ["lib", "image", "app"])

    def test_breakpoint_diagnosis_matches_verification(self):
        self.write_all()
        os.remove(self.layer_path("image"))

        with self.assertRaises(Exception):
            in_toto_verify(
                self.layout,
                {self.alice_pub["keyid"]: self.alice_pub},
                link_dir_path=self.link_dir,
            )

        diagnosis = self.diagnose()
        self.assertIs(diagnosis.verdict, ChainVerdict.PARTIALLY_VERIFIED)
        self.assertFalse(diagnosis.is_acceptable())
        self.assertEqual(diagnosis.first_break.layer_id, "image")
        self.assertEqual(diagnosis.first_break.index, 1)
        # Layers before and after the break are reported explicitly.
        self.assertEqual(diagnosis.verified_layers, ["lib", "app"])
        self.assertFalse(diagnosis.layers[2].continuity_verified)


if __name__ == "__main__":
    unittest.main()


class TestAdditionalBranches(ProvenanceFixture):
    """Coverage for less common diagnosis branches and edge cases."""

    def test_proof_location_accepts_string_value(self):
        self.write_all()
        diagnosis = self.diagnose(proof_locations={"image": "bundled"})
        self.assertIs(diagnosis.layers[1].status, LayerStatus.VERIFIED)

    def test_store_without_proof_store_is_unavailable(self):
        self.write_all()
        diagnosis = self.diagnose(
            proof_locations={"image": ProofLocation.STORE}
        )
        layer = diagnosis.layers[1]
        self.assertIs(layer.status, LayerStatus.UNAVAILABLE)
        self.assertIn("no store was provided", layer.reason)

    def test_file_proof_store_rejects_bad_directory_type(self):
        with self.assertRaises(ValueError):
            proofchain.FileProofStore(123)

    def test_file_store_read_error_is_unavailable(self):
        store_dir = tempfile.mkdtemp(dir=os.getcwd())
        try:
            with open(os.path.join(store_dir, "image.json"), "w") as fp:
                fp.write("{}")
            os.chmod(os.path.join(store_dir, "image.json"), 0o000)
            store = proofchain.FileProofStore(store_dir)
            if os.access(os.path.join(store_dir, "image.json"), os.R_OK):
                self.skipTest("running as privileged user")
            raw, status, _ = proofchain._fetch_from_store(
                store, "image", "link"
            )
            self.assertIsNone(raw)
            self.assertIs(status, LayerStatus.UNAVAILABLE)
        finally:
            os.chmod(os.path.join(store_dir, "image.json"), 0o644)
            shutil.rmtree(store_dir)

    def test_store_unexpected_exception_is_unavailable(self):
        self.write_all()
        os.remove(self.layer_path("image"))
        store = _FakeStore(errors={"image": RuntimeError("boom")})
        layer = self.diagnose(proof_store=store).layers[1]
        self.assertIs(layer.status, LayerStatus.UNAVAILABLE)
        self.assertIn("failed unexpectedly", layer.reason)

    def test_store_answer_none_is_missing_from_store(self):
        self.write_all()
        os.remove(self.layer_path("image"))
        layer = self.diagnose(proof_store=_FakeStore()).layers[1]
        self.assertIs(layer.status, LayerStatus.MISSING_FROM_STORE)
        self.assertIn("deletion", layer.missing_meaning)

    def test_bytes_and_string_proofs_parse(self):
        self.write_all()
        metadata = Metablock(signed=copy.deepcopy(self.links["image"]))
        metadata.create_signature(self.bob)
        document = json.dumps(metadata.to_dict()).encode("utf-8")

        store = _FakeStore(
            proofs={
                "lib": self.links["lib"],
                "image": document,
            }
        )
        # Store returns raw dict for lib and bytes for image.
        diagnosis = self.diagnose()
        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)

        # Exercise the bytes/str parse paths directly.
        parsed, fmt, _ = proofchain._parse_one(document, 1)
        self.assertEqual(fmt, "metablock")
        self.assertEqual(parsed.get_payload().name, "image")

        parsed, fmt, _ = proofchain._parse_one(
            Metablock(signed=copy.deepcopy(self.links["image"])), 1
        )
        self.assertEqual(fmt, "metadata")

    def test_invalid_utf8_bytes_are_unverifiable(self):
        with self.assertRaises(proofchain._UnparseableProofError):
            proofchain._parse_one(b"\xff\xfe", 1)

    def test_non_dict_document_is_unverifiable(self):
        with self.assertRaises(proofchain._UnparseableProofError):
            proofchain._parse_one([1, 2, 3], 1)

    def test_non_integer_version_is_unverifiable(self):
        self.write_all()
        with open(self.layer_path("image"), encoding="utf8") as fp:
            document = json.load(fp)
        document["provenanceFormatVersion"] = "one"
        with open(self.layer_path("image"), "w", encoding="utf8") as fp:
            json.dump(document, fp)

        layer = self.diagnose().layers[1]
        self.assertIs(layer.status, LayerStatus.UNVERIFIABLE)
        self.assertIn("non-integer", layer.reason)

    def test_metadata_object_that_does_not_parse_is_unverifiable(self):
        class Broken(Metablock):
            def get_payload(self):
                raise ValueError("no payload")

        with self.assertRaises(proofchain._UnparseableProofError):
            proofchain._parse_one(Broken(signed=Link(name="x")), 1)

    def test_unparseable_sibling_is_ignored_when_one_parses(self):
        raw_docs = [
            {"signed": None},
            Metablock(signed=copy.deepcopy(self.links["lib"])),
        ]
        docs, _, _, problem = proofchain._parse_proofs(raw_docs, 1)
        self.assertIsNone(problem)
        self.assertEqual(len(docs), 1)

    def test_conflicting_valid_proofs_are_tampered(self):
        # Two valid per-functionary link files that disagree.
        steps = [
            Step(
                name="lib",
                pubkeys=[self.alice_pub["keyid"], self.bob_pub["keyid"]],
                threshold=1,
            )
        ]
        layout = Metablock(
            signed=Layout(
                steps=steps,
                keys={
                    self.alice_pub["keyid"]: self.alice_pub,
                    self.bob_pub["keyid"]: self.bob_pub,
                },
            )
        )
        layout.create_signature(self.alice)

        first = Link(
            name="lib",
            materials={"a": _hash(SHA_A)},
            products={"b": _hash(SHA_B)},
        )
        second = Link(
            name="lib",
            materials={"a": _hash(SHA_C)},
            products={"b": _hash(SHA_B)},
        )
        # Filenames are keyid-derived, so write each signer's own file.
        self.dump_link(
            "lib",
            first,
            signer=self.alice,
            path=os.path.join(
                self.link_dir,
                FILENAME_FORMAT.format(
                    step_name="lib", keyid=self.alice_pub["keyid"]
                ),
            ),
        )
        self.dump_link(
            "lib",
            second,
            signer=self.bob,
            path=os.path.join(
                self.link_dir,
                FILENAME_FORMAT.format(
                    step_name="lib", keyid=self.bob_pub["keyid"]
                ),
            ),
        )

        diagnosis = diagnose_provenance_chain(
            layout, link_dir_path=self.link_dir
        )
        self.assertIs(diagnosis.layers[0].status, LayerStatus.TAMPERED)
        self.assertIn("disagree", diagnosis.layers[0].reason)
        self.assertIs(diagnosis.verdict, ChainVerdict.REJECTED)

    def test_artifact_check_error_is_ignored(self):
        self.write_all()
        with unittest.mock.patch(
            "in_toto.proofchain.record_artifacts_as_dict",
            side_effect=OSError("nope"),
        ):
            diagnosis = self.diagnose(artifact_base_path=self.link_dir)
        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)

    def test_artifact_check_handles_missing_hash_algorithm(self):
        self.write_all()
        link = Link(
            name="app",
            materials={"image.tar": _hash(SHA_C)},
            products={"app.bin": {"sha512": "e" * 128}},
        )
        self.dump_link("app", link)

        with open(
            os.path.join(self.link_dir, "app.bin"), "w", encoding="utf8"
        ) as fp:
            fp.write("content")

        diagnosis = self.diagnose(artifact_base_path=self.link_dir)
        self.assertIs(diagnosis.layers[2].status, LayerStatus.VERIFIED)

    def test_command_alignment_is_not_part_of_diagnosis(self):
        """Diagnosis does not fail on a non-matching expected command."""
        self.write_all()
        # Re-sign so the changed layout is otherwise fully valid.
        self.layout.signed.steps[0].expected_command = ["not", "the", "cmd"]
        self.layout.signatures = []
        self.layout.create_signature(self.alice)
        diagnosis = self.diagnose()
        self.assertIs(diagnosis.verdict, ChainVerdict.VERIFIED)

    def test_deep_nesting_limit(self):
        diagnosis = proofchain.diagnose_provenance_chain(
            self.layout, _depth=proofchain._MAX_NESTING + 1
        )
        self.assertIs(diagnosis.verdict, ChainVerdict.UNVERIFIABLE)
        self.assertIn("nesting", diagnosis.root_error)

    def test_non_layout_root(self):
        link_metadata = Metablock(signed=Link(name="not-a-layout"))
        diagnosis = proofchain.diagnose_provenance_chain(
            link_metadata, link_dir_path=self.link_dir
        )
        self.assertIs(diagnosis.verdict, ChainVerdict.UNVERIFIABLE)
        self.assertIn("does not contain a layout", diagnosis.root_error)

    def test_unparseable_root_payload(self):
        class Broken(Metablock):
            def get_payload(self):
                raise ValueError("bad payload")

        diagnosis = proofchain.diagnose_provenance_chain(
            Broken(signed=Link(name="x")), link_dir_path=self.link_dir
        )
        self.assertIs(diagnosis.verdict, ChainVerdict.UNVERIFIABLE)
        self.assertIn("cannot be parsed", diagnosis.root_error)

    def test_render_without_breakpoint_and_with_root_error(self):
        diagnosis = proofchain.ChainDiagnosis(
            verdict=ChainVerdict.UNVERIFIABLE,
            root_error="something went wrong",
        )
        rendered = diagnosis.render()
        self.assertIn("root layout: something went wrong", rendered)
        self.assertIn("Breakpoint: none", rendered)

    def test_render_breakpoint_without_remediation(self):
        bp = proofchain.Breakpoint(
            layer_id="x",
            index=0,
            path=("x",),
            status=LayerStatus.NOT_EVALUATED,
            expected_proof_type="link",
            expected_proof_files=(),
            location=None,
            reason="not evaluated",
        )
        rendered = proofchain.ChainDiagnosis(
            first_break=bp, verdict=ChainVerdict.UNVERIFIABLE
        ).render()
        self.assertIn("Breakpoint at layer 'x'", rendered)
        self.assertNotIn("retryable", rendered)

    def test_render_tamper_and_isolation_markers(self):
        layer = proofchain.LayerDiagnosis(
            layer_id="x",
            index=0,
            path=("x",),
            status=LayerStatus.TAMPERED,
            reason="mismatch",
            tamper_details=(
                {
                    "path": "f",
                    "expected": "aa",
                    "actual": "bb",
                },
            ),
        )
        rendered = proofchain.ChainDiagnosis(layers=[layer]).render()
        self.assertIn("content mismatch for 'f'", rendered)
