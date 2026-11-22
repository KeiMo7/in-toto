# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  proofchain.py

<Purpose>
  Breakpoint diagnosis and opt-in partial verification for provenance proof
  chains.

  The regular verification workflow in ``in_toto.verifylib`` is deliberately
  all-or-nothing: the first missing, malformed or invalid link aborts
  verification and the caller only learns that the chain is incomplete. This
  module adds a *read-only diagnosis* on top of the same verification
  primitives. It does not replace, weaken or otherwise change the regular
  verification result.

  Diagnosis distinguishes these layer states:

  * ``VERIFIED`` -- the proof exists, is signed by enough authorized
    functionaries, and its content is consistent with the artifact and with
    the previous layer.
  * ``MISSING_NOT_BUNDLED`` / ``MISSING_FROM_STORE`` -- no proof was found.
    The two are kept apart because they mean different things: a proof that
    was not shipped with an artifact is usually a packaging oversight, while
    a proof absent from a *reachable* independent store may have been deleted.
  * ``UNAVAILABLE`` / ``TIMEOUT`` -- the proof store could not be reached or
    did not answer in time. This is a degraded condition, not evidence that
    the proof is invalid, and it is retryable.
  * ``UNVERIFIABLE`` -- the proof was found but its format (or format version)
    is not understood. This is *not* the same as a verification failure: a
    too-new format version explicitly asks for an upgrade instead of
    declaring the proof corrupt.
  * ``PENDING_SIGNATURES`` -- the proof exists and its present signatures are
    valid, but a required co-signature is missing. A missing co-signature is
    **pending**, never "invalid".
  * ``INVALID_SIGNATURE`` -- a signature is present but does not verify.
  * ``TAMPERED`` -- signatures verify, but the signed content does not match
    the artifact or the previous layer.

  Multi-signature semantics are fixed as follows:

  ===========================================  ===============================
  Observation                                   Diagnosis
  ===========================================  ===============================
  valid signatures >= threshold                 ``VERIFIED``
  some valid, some required ones *absent*       ``PENDING_SIGNATURES``
  a present signature does not verify           ``INVALID_SIGNATURE``
  valid signatures < threshold, none broken     ``PENDING_SIGNATURES``
  ===========================================  ===============================

  A proof whose required co-signature is merely absent is therefore always
  reported as pending, so that independent verifiers reach the same
  conclusion. It is never silently accepted as verified and never called
  invalid.

  Overall verdicts:

  * ``VERIFIED`` -- every layer verified and chain continuity holds.
  * ``PARTIALLY_VERIFIED`` -- no layer is present-but-bad, but at least one is
    missing, unreachable, timed out, pending or not evaluated. Accepted only
    when the caller explicitly opts into tolerant mode *and* at least one
    layer verified; confidence is lower than for a fully verified chain.
  * ``REJECTED`` -- at least one layer is present but invalid or tampered, or
    the root layout itself is invalid/expired.
  * ``UNVERIFIABLE`` -- a layer exists but cannot be interpreted with the
    supported proof formats.

  Proof storage is modelled explicitly: proofs may be bundled with the
  artifact (searched in the link directory) or live in an independent
  ``ProofStore``. A store that raises :class:`ProofStoreUnavailable` or
  :class:`ProofStoreTimeout` yields ``UNAVAILABLE``/``TIMEOUT``, and a store
  that answers but returns nothing yields ``MISSING_FROM_STORE``.

  Format versioning: a proof document may carry a top-level
  ``provenanceFormatVersion`` integer (or ``{"_provenance": {"formatVersion":
  N}}``). Versions above ``in_toto.settings.PROVENANCE_MAX_FORMAT_VERSION``
  are reported as ``UNVERIFIABLE`` with an upgrade recommendation.

"""

import enum
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import securesystemslib.exceptions
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.settings
from in_toto.exceptions import (
    LayoutExpiredError,
    ProofStoreError,
    ProofStoreTimeout,
    ProofStoreUnavailable,
    SignatureVerificationError,
)
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT, Layout
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metadata
from in_toto.runlib import record_artifacts_as_dict
from in_toto.verifylib import verify_layout_expiration

LOG = logging.getLogger(__name__)

_MAX_NESTING = 32


class LayerStatus(str, enum.Enum):
    """Diagnosis status of a single proof chain layer."""

    VERIFIED = "verified"
    MISSING_NOT_BUNDLED = "missing_not_bundled"
    MISSING_FROM_STORE = "missing_from_store"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    PENDING_SIGNATURES = "pending_signatures"
    UNVERIFIABLE = "unverifiable"
    INVALID_SIGNATURE = "invalid_signature"
    TAMPERED = "tampered"
    NOT_EVALUATED = "not_evaluated"


class ChainVerdict(str, enum.Enum):
    """Overall verdict of a diagnosed proof chain."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    REJECTED = "rejected"
    UNVERIFIABLE = "unverifiable"


class Confidence(str, enum.Enum):
    """Confidence associated with a verdict."""

    FULL = "full"
    REDUCED = "reduced"
    NONE = "none"


class ProofLocation(str, enum.Enum):
    """Where a layer's proof is expected to live."""

    AUTO = "auto"
    BUNDLED = "bundled"
    STORE = "store"


# Statuses that represent a content failure. Tolerant mode must never accept
# a chain that contains one of these.
_FAILED_STATUSES = frozenset(
    {LayerStatus.INVALID_SIGNATURE, LayerStatus.TAMPERED}
)

_RETRYABLE_STATUSES = frozenset({LayerStatus.UNAVAILABLE, LayerStatus.TIMEOUT})

_REMEDIATION = {
    LayerStatus.MISSING_NOT_BUNDLED: (
        "Ship the missing proof together with the artifact, or point the "
        "diagnosis at the independent store that holds it."
    ),
    LayerStatus.MISSING_FROM_STORE: (
        "The proof store was reachable but returned no proof. Check its "
        "retention, deletion and access policy, then retry once repaired."
    ),
    LayerStatus.UNAVAILABLE: (
        "The proof store is unreachable. Treat this as a degraded condition, "
        "not as an invalid proof, and retry with backoff after checking "
        "connectivity and credentials."
    ),
    LayerStatus.TIMEOUT: (
        "Fetching the proof timed out. Retry with a longer timeout or less "
        "load; do not treat the proof as invalid."
    ),
    LayerStatus.PENDING_SIGNATURES: (
        "One or more required co-signatures are absent. The proof is pending, "
        "not invalid; collect the missing signature(s) and re-run."
    ),
    LayerStatus.INVALID_SIGNATURE: (
        "A present signature does not verify. Quarantine the proof and "
        "investigate its origin."
    ),
    LayerStatus.TAMPERED: (
        "The signed content does not match the artifact or the previous "
        "layer. Quarantine the artifact and investigate; retrying will not "
        "help."
    ),
}


class ProofStore:
    """Interface for an independent provenance proof store.

    Implementations return a raw proof document (``dict``, ``bytes``/``str``
    with JSON content, or a :class:`Metadata`) or ``None`` if the store is
    reachable but has no proof for the requested layer.

    Transient failures must be signalled with :class:`ProofStoreUnavailable`
    (or :class:`ProofStoreTimeout` for timeouts), never with ``None``.
    """

    name = "proof store"

    def fetch(self, layer_id: str, proof_type: str):
        """Return the proof document for ``layer_id`` or ``None``."""
        raise NotImplementedError  # pragma: no cover

    def __str__(self):
        return self.name


def _render_layer(layer):
    """Render one layer of a human-readable chain report."""
    line = f"  [{layer.index + 1}] {layer.layer_id}: {layer.status.value}"
    if layer.location:
        line += f" ({layer.location})"
    if "isolation" in layer.details:
        line += " [evaluated in isolation]"

    lines = [line]
    lines.extend(
        "      content mismatch for "
        f"'{tamper.get('path')}': expected {tamper.get('expected')}, "
        f"actual {tamper.get('actual')}"
        for tamper in layer.tamper_details
    )
    if layer.nested:
        lines.extend(
            f"      {nested_line}"
            for nested_line in layer.nested.render().splitlines()
        )
    return lines


def _render_breakpoint(first_break):
    """Render the breakpoint section of a human-readable chain report."""
    if first_break is None:
        return ["Breakpoint: none"]

    suffix = (
        f" ({', '.join(first_break.expected_proof_files)})"
        if first_break.expected_proof_files
        else ""
    )
    lines = [
        f"Breakpoint at layer '{first_break.layer_id}' "
        f"(#{first_break.index + 1}): {first_break.status.value}",
        f"  expected proof type: {first_break.expected_proof_type}{suffix}",
        f"  reason: {first_break.reason}",
    ]
    if first_break.remediation:
        lines.append(f"  remediation: {first_break.remediation}")
    if first_break.retryable:
        lines.append("  retryable: yes")
    return lines


class FileProofStore(ProofStore):
    """Proof store backed by a local directory.

    Proofs are looked up as ``<layer id>.json``. A missing directory is
    reported as unavailable rather than as a missing proof.
    """

    def __init__(self, directory):
        if not isinstance(directory, str):
            raise ValueError("'directory' must be a string")

        self.directory = directory
        self.name = f"file proof store '{directory}'"

    def fetch(self, layer_id, proof_type):  # noqa: ARG002
        if not os.path.isdir(self.directory):
            raise ProofStoreUnavailable(
                f"Proof store directory '{self.directory}' is not reachable"
            )

        path = os.path.join(self.directory, f"{layer_id}.json")
        try:
            with open(path, encoding="utf8") as fp:
                return json.load(fp)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise ProofStoreUnavailable(
                f"Could not read proof '{path}' from '{self.directory}': {e}"
            ) from e


@dataclass
class SignatureReport:
    """Result of evaluating a layer's signatures against a step."""

    valid: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    unauthorized: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def valid_count(self):
        """Return the number of distinct valid signers."""
        return len(set(self.valid))


@dataclass
class LayerDiagnosis:
    """Diagnosis of one layer of a provenance chain."""

    layer_id: str
    index: int
    path: tuple[str, ...]
    status: LayerStatus
    reason: str
    expected_proof_type: str = "link"
    expected_proof_files: tuple[str, ...] = ()
    location: Optional[str] = None
    locations_searched: tuple[str, ...] = ()
    confidence: Confidence = Confidence.NONE
    retryable: bool = False
    remediation: Optional[str] = None
    required_signers: tuple[str, ...] = ()
    valid_signers: tuple[str, ...] = ()
    invalid_signers: tuple[str, ...] = ()
    absent_signers: tuple[str, ...] = ()
    unauthorized_signers: tuple[str, ...] = ()
    source_format: Optional[str] = None
    format_version: Optional[int] = None
    continuity_verified: bool = True
    tamper_details: tuple[dict[str, Any], ...] = ()
    missing_meaning: Optional[str] = None
    nested: Optional["ChainDiagnosis"] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        """Return a JSON-serializable representation."""
        return {
            "layer_id": self.layer_id,
            "index": self.index,
            "path": list(self.path),
            "status": self.status.value,
            "reason": self.reason,
            "expected_proof_type": self.expected_proof_type,
            "expected_proof_files": list(self.expected_proof_files),
            "location": self.location,
            "locations_searched": list(self.locations_searched),
            "confidence": self.confidence.value,
            "retryable": self.retryable,
            "remediation": self.remediation,
            "required_signers": list(self.required_signers),
            "valid_signers": list(self.valid_signers),
            "invalid_signers": list(self.invalid_signers),
            "absent_signers": list(self.absent_signers),
            "unauthorized_signers": list(self.unauthorized_signers),
            "source_format": self.source_format,
            "format_version": self.format_version,
            "continuity_verified": self.continuity_verified,
            "tamper_details": list(self.tamper_details),
            "missing_meaning": self.missing_meaning,
            "nested": self.nested.to_dict() if self.nested else None,
            "details": {
                key: value
                for key, value in self.details.items()
                if not key.startswith("_")
            },
        }


@dataclass
class Breakpoint:
    """The first layer at which a chain could not be verified."""

    layer_id: str
    index: int
    path: tuple[str, ...]
    status: LayerStatus
    expected_proof_type: str
    expected_proof_files: tuple[str, ...]
    location: Optional[str]
    reason: str
    remediation: Optional[str] = None
    retryable: bool = False

    def to_dict(self):
        """Return a JSON-serializable representation."""
        return {
            "layer_id": self.layer_id,
            "index": self.index,
            "path": list(self.path),
            "status": self.status.value,
            "expected_proof_type": self.expected_proof_type,
            "expected_proof_files": list(self.expected_proof_files),
            "location": self.location,
            "reason": self.reason,
            "remediation": self.remediation,
            "retryable": self.retryable,
        }


@dataclass
class ChainDiagnosis:
    """Diagnosis of a full provenance chain."""

    layers: list[LayerDiagnosis] = field(default_factory=list)
    verdict: ChainVerdict = ChainVerdict.UNVERIFIABLE
    confidence: Confidence = Confidence.NONE
    first_break: Optional[Breakpoint] = None
    tolerant: bool = False
    summary_link: Optional[Link] = None
    root_error: Optional[str] = None

    @property
    def verified_layers(self):
        """Return ids of layers whose status is VERIFIED."""
        return [
            layer.layer_id
            for layer in self.layers
            if layer.status is LayerStatus.VERIFIED
        ]

    @property
    def failed_layers(self):
        """Return ids of layers whose content failed verification."""
        return [
            layer.layer_id
            for layer in self.layers
            if layer.status in _FAILED_STATUSES
        ]

    def is_acceptable(self):
        """Return whether the verdict may be accepted.

        Full verification is always acceptable. A partial result is only
        acceptable when tolerant mode was explicitly requested and at least
        one layer actually verified. Failures and unverifiable layers are
        never acceptable.
        """
        if self.verdict is ChainVerdict.VERIFIED:
            return True
        if self.verdict is ChainVerdict.PARTIALLY_VERIFIED:
            return bool(self.tolerant and self.verified_layers)
        return False

    def to_dict(self):
        """Return a JSON-serializable representation."""
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "tolerant": self.tolerant,
            "acceptable": self.is_acceptable(),
            "verified_layers": self.verified_layers,
            "failed_layers": self.failed_layers,
            "first_break": self.first_break.to_dict()
            if self.first_break
            else None,
            "root_error": self.root_error,
            "layers": [layer.to_dict() for layer in self.layers],
        }

    def to_json(self):
        """Return an indented JSON representation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def render(self):
        """Return a human-readable report."""
        lines = [
            f"Provenance chain diagnosis: {self.verdict.value.upper()} "
            f"(confidence: {self.confidence.value})"
        ]
        if self.root_error:
            lines.append(f"  root layout: {self.root_error}")

        for layer in self.layers:
            lines.extend(_render_layer(layer))

        lines.extend(_render_breakpoint(self.first_break))
        return "\n".join(lines)


def _resolve_authorized_key(layout, authorized_keyid):
    """Resolve an authorized keyid to a (key, canonical keyid) pair.

    A keyid listed in a step may be a main key or a subkey. Subkeys resolve to
    their main key, which is also the unit counted towards thresholds.
    """
    key = layout.keys.get(authorized_keyid)
    if key is not None:
        return key, key.get("keyid", authorized_keyid)

    for main_keyid, main_key in layout.keys.items():
        if authorized_keyid in main_key.get("subkeys", {}):
            return main_key, main_keyid

    return None, authorized_keyid


def _accepted_signature_keyids(layout, authorized_keyid):
    """Return signature keyids accepted for an authorized keyid.

    If the authorized keyid is a main key, its subkeys are accepted too. If it
    is itself a subkey, only that subkey is accepted, mirroring the regular
    authorization logic.
    """
    main_key = layout.keys.get(authorized_keyid)
    if main_key is not None:
        return [authorized_keyid] + list(main_key.get("subkeys", {}))

    return [authorized_keyid]


def _signature_keyids(metadata):
    """Return the keyids of signatures present on a Metadata object."""
    signatures = getattr(metadata, "signatures", None)
    if isinstance(signatures, dict):
        return list(signatures)
    if isinstance(signatures, list):
        return [
            signature.get("keyid")
            for signature in signatures
            if isinstance(signature, dict)
        ]
    return []


def _evaluate_signatures(docs, step, layout):
    """Evaluate signatures of one or more proofs against a step.

    ``docs`` is a list of parsed ``Metadata`` objects. A layer may be backed by
    a single multi-signed proof or by several per-functionary link files; both
    are handled uniformly by looking for each authorized key in any document.
    """
    report = SignatureReport()
    present = set()
    for metadata in docs:
        present.update(keyid for keyid in _signature_keyids(metadata) if keyid)

    accepted = set()
    seen_canonical = set()
    for authorized_keyid in step.pubkeys:
        key, canonical_keyid = _resolve_authorized_key(layout, authorized_keyid)
        if key is None or canonical_keyid in seen_canonical:
            continue
        seen_canonical.add(canonical_keyid)

        keyids = _accepted_signature_keyids(layout, authorized_keyid)
        accepted.update(keyids)

        if not present.intersection(keyids):
            report.absent.append(canonical_keyid)
            continue

        verified = False
        error = None
        for metadata in docs:
            if not set(_signature_keyids(metadata)).intersection(keyids):
                continue
            try:
                metadata.verify_signature(key)
            except (
                SignatureVerificationError,
                KeyExpirationError,
                securesystemslib.exceptions.FormatError,
                KeyError,
                ValueError,
            ) as e:
                error = f"{type(e).__name__}: {e}"
            else:
                verified = True
                break

        if verified:
            report.valid.append(canonical_keyid)
        else:
            report.invalid.append(canonical_keyid)
            report.errors[canonical_keyid] = error or "signature did not verify"

    report.unauthorized = sorted(present - accepted)
    return report


def _signature_status(step, report):
    """Classify a signature report into a layer status and reason."""
    threshold = step.threshold
    if report.valid_count >= threshold:
        return (
            LayerStatus.VERIFIED,
            f"{report.valid_count} authorized signature(s) verified "
            f"(threshold {threshold})",
        )

    if report.invalid:
        return (
            LayerStatus.INVALID_SIGNATURE,
            "Present signature(s) from "
            f"{', '.join(report.invalid)} do not verify: "
            f"{report.errors.get(report.invalid[0], 'unknown error')}",
        )

    return (
        LayerStatus.PENDING_SIGNATURES,
        f"Only {report.valid_count} of {threshold} required signature(s) "
        "present; missing co-signature(s) from "
        f"{', '.join(report.absent) or 'unknown signers'}. The proof is "
        "pending, not invalid.",
    )


def _hashes_disagree(first, second):
    """Return whether two hash dictionaries disagree on a shared algorithm."""
    shared = set(first) & set(second)
    return any(first[algorithm] != second[algorithm] for algorithm in shared)


def _mismatch(path, expected, actual, kind):
    """Build a mismatch record for the given artifact path."""
    shared = sorted(set(expected) & set(actual))
    algorithm = shared[0] if shared else "sha256"
    return {
        "path": path,
        "algorithm": algorithm,
        "expected": expected.get(algorithm),
        "actual": actual.get(algorithm),
        "kind": kind,
    }


def _artifact_mismatches(link, artifact_base_path):
    """Compare a link's declared products with the artifacts on disk."""
    if not artifact_base_path or not link.products:
        return []

    try:
        actual_hashes = record_artifacts_as_dict(
            list(link.products),
            base_path=artifact_base_path,
            exclude_patterns=[],
        )
    except (OSError, ValueError) as e:
        LOG.info("Could not check artifacts on disk: %s", e)
        return []

    mismatches = []
    for path, expected in link.products.items():
        actual = actual_hashes.get(path)
        if actual is None:
            continue
        if _hashes_disagree(expected, actual):
            mismatches.append(_mismatch(path, expected, actual, "artifact"))
    return mismatches


def _cross_layer_mismatches(previous_link, link):
    """Compare a layer's materials with the previous layer's products."""
    mismatches = []
    for path in sorted(set(previous_link.products) & set(link.materials)):
        expected = previous_link.products[path]
        actual = link.materials[path]
        if _hashes_disagree(expected, actual):
            mismatches.append(_mismatch(path, expected, actual, "cross_layer"))
    return mismatches


def _different_payloads(docs):
    """Return whether parsed link proofs of a layer disagree with one another."""
    signatures = set()
    for metadata in docs:
        payload = metadata.get_payload()
        if payload.type_ != "link":
            continue
        signatures.add((repr(payload.materials), repr(payload.products)))

    return len(signatures) > 1


class _UnparseableProofError(Exception):
    """Internal marker for a proof that cannot be interpreted."""

    def __init__(self, message, upgrade=False, version=None):
        super().__init__(message)
        self.upgrade = upgrade
        self.version = version


def _version_from_document(data):
    """Extract an integer proof format version from a raw document."""
    version = None
    if isinstance(data, dict):
        version = data.get("provenanceFormatVersion")
        if version is None:
            provenance = data.get("_provenance")
            if isinstance(provenance, dict):
                version = provenance.get("formatVersion")

    if version is None:
        return None
    if not isinstance(version, int) or isinstance(version, bool):
        raise _UnparseableProofError(
            "Proof declares a non-integer format version "
            f"'{version!r}'; it cannot be interpreted."
        )
    return version


def _source_format(data):
    """Return the proof container format name, or None if unrecognized."""
    if not isinstance(data, dict):
        return None
    if "payload" in data and "payloadType" in data:
        return "dsse"
    if "signed" in data:
        return "metablock"
    return None


def _parse_one(raw, max_format_version):  # noqa: C901
    """Parse a single proof document.

    Returns ``(metadata, source_format, version)``. Raises
    ``_UnparseableProofError`` with a human-readable reason if the document cannot
    be interpreted.
    """
    if isinstance(raw, Metadata):
        try:
            raw.get_payload()
        except Exception as e:
            raise _UnparseableProofError(
                f"Proof payload cannot be parsed: {e}"
            ) from e
        return raw, "metadata", None

    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise _UnparseableProofError(
                f"Proof bytes are not valid UTF-8: {e}"
            ) from e

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise _UnparseableProofError(f"Proof is not valid JSON: {e}") from e

    if not isinstance(raw, dict):
        raise _UnparseableProofError(
            "Proof document has an unrecognized format "
            f"({type(raw).__name__}); cannot verify it."
        )

    version = _version_from_document(raw)

    if version is not None and version > max_format_version:
        raise _UnparseableProofError(
            f"Proof declares format version {version}, but this verifier "
            f"supports at most version {max_format_version}. The proof is "
            "not corrupt; the verifier needs an upgrade.",
            upgrade=True,
            version=version,
        )

    source_format = _source_format(raw)
    if source_format is None:
        raise _UnparseableProofError(
            "Proof document has an unrecognized container format; it cannot "
            "be verified but is not evidence of failure."
        )

    try:
        metadata = Metadata.from_dict(raw)
        metadata.get_payload()
    except (
        securesystemslib.exceptions.FormatError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ) as e:
        raise _UnparseableProofError(
            f"Proof document cannot be parsed as in-toto metadata: {e}"
        ) from e

    return metadata, source_format, version


def _parse_proofs(raw_docs, max_format_version):
    """Parse all documents of a layer.

    Returns ``(docs, source_format, version, problem)``. ``problem`` is a
    ``(reason, remediation)`` tuple if none of the documents can be parsed.
    """
    docs = []
    problems = []
    upgrades = []
    source_format = None
    version = None
    for raw in raw_docs:
        try:
            metadata, fmt, ver = _parse_one(raw, max_format_version)
        except _UnparseableProofError as e:
            problems.append(str(e))
            if e.version is not None:
                version = e.version
            if e.upgrade:
                upgrades.append(str(e))
            continue
        docs.append(metadata)
        source_format = source_format or fmt
        version = version if version is not None else ver

    if docs:
        if problems:
            LOG.info("Ignoring %d unparseable sibling proof(s)", len(problems))
        return docs, source_format, version, None

    reason = "; ".join(problems) or "Proof could not be interpreted"
    if upgrades:
        remediation = (
            "Upgrade in-toto to a version that supports the proof format "
            "version declared by this proof."
        )
    else:
        remediation = (
            "Check the proof's type, format and version; a verifier that "
            "understands this format is required."
        )
    return [], source_format, version, (reason, remediation)


def _bundled_filenames(step, layout):
    """Return expected bundled proof filenames for a step."""
    return [
        FILENAME_FORMAT.format(step_name=step.name, keyid=keyid)
        for authorized_keyid in step.pubkeys
        for keyid in _accepted_signature_keyids(layout, authorized_keyid)
    ]


def _load_bundled(step, layout, link_dir_path):
    """Load all bundled proofs for a step.

    Returns ``(raw_docs, searched_paths)``. Files that exist but cannot be
    read are skipped with a log message; a decoding failure keeps the raw text
    so that the proof is diagnosed as unverifiable instead of missing.
    """
    raw_docs = []
    searched = []
    for filename in _bundled_filenames(step, layout):
        path = os.path.join(link_dir_path, filename)
        searched.append(path)
        try:
            with open(path, encoding="utf8") as fp:
                text = fp.read()
        except FileNotFoundError:
            continue
        except OSError as e:
            LOG.info("Could not read bundled proof '%s': %s", path, e)
            continue

        try:
            raw_docs.append(json.loads(text))
        except json.JSONDecodeError:
            raw_docs.append(text)

    return raw_docs, tuple(searched)


def _fetch_from_store(store, layer_id, proof_type):
    """Fetch a proof from a store, mapping failures to diagnosis statuses.

    Returns ``(raw, status, reason)``; exactly one of raw/status is set.
    """
    try:
        raw = store.fetch(layer_id, proof_type)
    except (ProofStoreTimeout, TimeoutError) as e:
        return None, LayerStatus.TIMEOUT, f"Proof fetch timed out: {e}"
    except (ProofStoreError, OSError) as e:
        return (
            None,
            LayerStatus.UNAVAILABLE,
            f"Proof store '{store}' is unavailable: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return (
            None,
            LayerStatus.UNAVAILABLE,
            f"Proof store '{store}' failed unexpectedly: "
            f"{type(e).__name__}: {e}",
        )

    if raw is None:
        return None, LayerStatus.MISSING_FROM_STORE, "Proof not in store"
    return raw, None, None


def _missing_meaning(location, store_configured):
    """Explain what a missing proof means for the given storage layout."""
    if location is ProofLocation.STORE:
        return (
            "The proof is absent from a reachable independent store; this can "
            "indicate deletion, retention expiry or an access-policy issue."
        )
    if location is ProofLocation.BUNDLED:
        return (
            "The proof was not shipped with the artifact; this is usually a "
            "packaging or transfer oversight, not deletion."
        )
    if store_configured:
        return (
            "The proof was neither shipped nor found in a reachable store; "
            "check packaging first, then the store's deletion/retention "
            "policy."
        )
    return (
        "The proof was not shipped with the artifact; this is usually a "
        "packaging or transfer oversight, not deletion."
    )


def _probe_layer(step, layout, link_dir_path, store, location):  # noqa: C901
    """Locate a layer's proof.

    Returns a dict describing either the raw documents found, or a terminal
    status for the layer.
    """
    if not isinstance(location, ProofLocation):
        location = ProofLocation(location)

    raw_docs = []
    searched = ()
    resolved_location = None

    if location in (ProofLocation.AUTO, ProofLocation.BUNDLED):
        raw_docs, searched = _load_bundled(step, layout, link_dir_path)
        if raw_docs:
            resolved_location = ProofLocation.BUNDLED

    store_status = None
    store_reason = None
    if not raw_docs and location in (ProofLocation.AUTO, ProofLocation.STORE):
        if store is None:
            if location is ProofLocation.STORE:
                return {
                    "status": LayerStatus.UNAVAILABLE,
                    "reason": "Layer is configured to use a proof store, but "
                    "no store was provided.",
                    "remediation": "Provide a ProofStore for this layer.",
                    "location": "store",
                    "searched": (),
                }
        else:
            fetched, store_status, store_reason = _fetch_from_store(
                store, step.name, "link"
            )
            if fetched is not None:
                raw_docs = [fetched]
                resolved_location = ProofLocation.STORE

    if not raw_docs:
        if store_status in (LayerStatus.UNAVAILABLE, LayerStatus.TIMEOUT):
            return {
                "status": store_status,
                "reason": store_reason,
                "remediation": _REMEDIATION[store_status],
                "location": "store",
                "searched": searched,
            }

        if location is ProofLocation.STORE or store is not None:
            status = LayerStatus.MISSING_FROM_STORE
            reason = "No proof was found for this layer in the proof store."
        else:
            status = LayerStatus.MISSING_NOT_BUNDLED
            reason = (
                "The proof was not shipped (bundled) with the artifact for "
                "this layer."
            )

        return {
            "status": status,
            "reason": reason,
            "remediation": _REMEDIATION[status],
            "missing_meaning": _missing_meaning(location, store is not None),
            "location": resolved_location
            or (
                "bundled"
                if location is ProofLocation.BUNDLED
                else ("store" if location is ProofLocation.STORE else None)
            ),
            "searched": searched,
        }

    return {
        "raw_docs": raw_docs,
        "location": resolved_location,
        "searched": searched,
    }


def _expected_files(step, layout, searched):
    """Return human-readable expected proof file names for a layer."""
    if searched:
        return tuple(os.path.basename(path) for path in searched)
    return tuple(_bundled_filenames(step, layout))


def _terminal_layer(step, index, probe, layout):
    """Build a LayerDiagnosis for a layer that could not be located."""
    return LayerDiagnosis(
        layer_id=step.name,
        index=index,
        path=(step.name,),
        status=probe["status"],
        reason=probe["reason"],
        expected_proof_type="link",
        expected_proof_files=_expected_files(
            step, layout, probe.get("searched", ())
        ),
        location=probe.get("location"),
        locations_searched=probe.get("searched", ()),
        retryable=probe["status"] in _RETRYABLE_STATUSES,
        remediation=probe.get("remediation"),
        missing_meaning=probe.get("missing_meaning"),
        continuity_verified=False,
    )


def _unverifiable_layer(  # noqa: PLR0913
    step, index, probe, layout, reason, remediation, version=None
):
    """Build a LayerDiagnosis for a proof that cannot be interpreted."""
    return LayerDiagnosis(
        layer_id=step.name,
        index=index,
        path=(step.name,),
        status=LayerStatus.UNVERIFIABLE,
        reason=reason,
        expected_proof_type="link",
        expected_proof_files=_expected_files(
            step, layout, probe.get("searched", ())
        ),
        location=probe.get("location"),
        locations_searched=probe.get("searched", ()),
        confidence=Confidence.NONE,
        retryable=False,
        remediation=remediation,
        format_version=version,
        continuity_verified=False,
    )


def _diagnose_proof_layer(  # noqa: PLR0913, PLR0917, RUF100
    step,
    index,
    docs,
    probe,
    source_format,
    version,
    layout,
    link_dir_path,
    proof_store,
    proof_locations,
    artifact_base_path,
    max_format_version,
    tolerant,
    recurse_sublayouts,
    depth,
):
    """Diagnose a located and parsed proof layer."""
    report = _evaluate_signatures(docs, step, layout)
    status, reason = _signature_status(step, report)

    layer = LayerDiagnosis(
        layer_id=step.name,
        index=index,
        path=(step.name,),
        status=status,
        reason=reason,
        expected_proof_type=docs[0].get_payload().type_,
        expected_proof_files=_expected_files(
            step, layout, probe.get("searched", ())
        ),
        location=probe.get("location"),
        locations_searched=probe.get("searched", ()),
        confidence=Confidence.FULL
        if status is LayerStatus.VERIFIED
        else Confidence.NONE,
        retryable=status in _RETRYABLE_STATUSES,
        remediation=_REMEDIATION.get(status),
        required_signers=tuple(step.pubkeys),
        valid_signers=tuple(report.valid),
        invalid_signers=tuple(report.invalid),
        absent_signers=tuple(report.absent),
        unauthorized_signers=tuple(report.unauthorized),
        source_format=source_format,
        format_version=version,
        continuity_verified=status is LayerStatus.VERIFIED,
    )

    if status is not LayerStatus.VERIFIED:
        return layer

    if len(docs) > 1 and _different_payloads(docs):
        layer.status = LayerStatus.TAMPERED
        layer.reason = (
            "Multiple valid proofs for this layer disagree on materials or "
            "products."
        )
        layer.remediation = _REMEDIATION[LayerStatus.TAMPERED]
        layer.confidence = Confidence.NONE
        return layer

    payload = docs[0].get_payload()

    if payload.type_ == "layout":
        if not recurse_sublayouts:
            layer.details["sublayout"] = "not evaluated (recursion disabled)"
            return layer

        keyid = report.valid[0] if report.valid else step.pubkeys[0]
        sub_layer_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=step.name, keyid=keyid
        )
        nested = diagnose_provenance_chain(
            docs[0],
            None,
            os.path.join(link_dir_path, sub_layer_dir),
            proof_store=proof_store,
            proof_locations=proof_locations,
            artifact_base_path=artifact_base_path,
            max_format_version=max_format_version,
            tolerant=tolerant,
            recurse_sublayouts=recurse_sublayouts,
            _depth=depth + 1,
            _verify_root=False,
        )
        layer.nested = nested
        layer.expected_proof_type = "layout"

        if nested.verdict is ChainVerdict.VERIFIED:
            layer.reason = "Delegated sublayout verified"
            if nested.summary_link is not None:
                layer.details["_summary_source"] = nested.summary_link
            return layer

        nested_break = nested.first_break
        if nested_break is not None:
            layer.path = (step.name,) + nested_break.path
            layer.status = nested_break.status
            layer.reason = (
                f"Delegated sublayout breakpoint '{nested_break.layer_id}': "
                f"{nested_break.status.value}: {nested_break.reason}"
            )
            layer.remediation = nested_break.remediation
            layer.retryable = nested_break.retryable
        elif nested.root_error:
            layer.status = LayerStatus.UNVERIFIABLE
            layer.reason = f"Delegated sublayout: {nested.root_error}"
            layer.remediation = "Inspect the nested chain diagnosis."
        else:
            layer.status = LayerStatus.UNVERIFIABLE
            layer.reason = "Delegated sublayout could not be verified"
            layer.remediation = "Inspect the nested chain diagnosis."
        layer.confidence = Confidence.NONE
        return layer

    link = payload
    tamper_details = list(_artifact_mismatches(link, artifact_base_path))
    if tamper_details:
        layer.status = LayerStatus.TAMPERED
        layer.reason = (
            "Signature(s) verify, but the signed product content does not "
            "match the artifact on disk."
        )
        layer.remediation = _REMEDIATION[LayerStatus.TAMPERED]
        layer.tamper_details = tuple(tamper_details)
        layer.confidence = Confidence.NONE

    return layer


def _summarize(layers, tolerant, root_error=None, root_verdict=None):
    """Compute the overall verdict from layer diagnoses."""
    if root_error is not None:
        return ChainDiagnosis(
            layers=layers,
            verdict=root_verdict or ChainVerdict.REJECTED,
            confidence=Confidence.NONE,
            root_error=root_error,
            tolerant=tolerant,
        )

    first_break = None
    for layer in layers:
        if layer.status is not LayerStatus.VERIFIED:
            first_break = Breakpoint(
                layer_id=layer.layer_id,
                index=layer.index,
                path=layer.path,
                status=layer.status,
                expected_proof_type=layer.expected_proof_type,
                expected_proof_files=layer.expected_proof_files,
                location=layer.location,
                reason=layer.reason,
                remediation=layer.remediation,
                retryable=layer.retryable,
            )
            break

    if any(layer.status in _FAILED_STATUSES for layer in layers):
        verdict = ChainVerdict.REJECTED
        confidence = Confidence.NONE
    elif any(layer.status is LayerStatus.UNVERIFIABLE for layer in layers):
        verdict = ChainVerdict.UNVERIFIABLE
        confidence = Confidence.NONE
    elif all(layer.status is LayerStatus.VERIFIED for layer in layers):
        verdict = ChainVerdict.VERIFIED
        confidence = Confidence.FULL
    else:
        verdict = ChainVerdict.PARTIALLY_VERIFIED
        confidence = Confidence.REDUCED

    return ChainDiagnosis(
        layers=layers,
        verdict=verdict,
        confidence=confidence,
        first_break=first_break,
        tolerant=tolerant,
    )


def _summary_link(layers, name):
    """Build a summary link from the first and last verified link layers."""
    records = [
        layer.details["_summary_source"]
        for layer in layers
        if layer.status is LayerStatus.VERIFIED
        and "_summary_source" in layer.details
    ]
    records = [record for record in records if isinstance(record, Link)]
    if not records:
        return None

    summary = Link(name=name)
    summary.materials = records[0].materials
    summary.products = records[-1].products
    summary.byproducts = records[-1].byproducts
    summary.command = records[-1].command
    return summary


def diagnose_provenance_chain(  # noqa: C901, PLR0912, PLR0913, PLR0915, PLR0917, RUF100
    metadata,
    layout_keys=None,
    link_dir_path=".",
    proof_store=None,
    proof_locations=None,
    artifact_base_path=None,
    max_format_version=None,
    tolerant=None,
    recurse_sublayouts=True,
    _depth=0,
    _verify_root=True,
):
    """Diagnose a provenance proof chain without changing verification.

    The function walks the steps of a layout in order and reports a status for
    each layer. It never raises for a broken chain: missing, unreachable,
    unverifiable, pending and tampered layers are all represented in the
    returned :class:`ChainDiagnosis`.

    Arguments:
      metadata: A :class:`Metadata` object containing the root layout.

      layout_keys (optional): A public key dictionary used to verify the root
          layout's signatures. If omitted, the root layout signature is not
          re-checked by diagnosis.

      link_dir_path (optional): Directory holding bundled proofs, using the
          regular ``<step>.<keyid prefix>.link`` naming.

      proof_store (optional): A :class:`ProofStore` for proofs that are not
          bundled with the artifact.

      proof_locations (optional): Mapping of layer id to
          :class:`ProofLocation`. Defaults to ``AUTO`` for every layer.

      artifact_base_path (optional): Directory against which declared product
          hashes are checked. If omitted, only cross-layer consistency is
          checked.

      max_format_version (optional): Highest supported proof format version.
          Defaults to ``in_toto.settings.PROVENANCE_MAX_FORMAT_VERSION``.

      tolerant (optional): Whether partial results may be accepted. Defaults to
          ``in_toto.settings.PROVENANCE_TOLERANT_MODE``. This does not relax
          any verification performed by this function; it only affects
          :meth:`ChainDiagnosis.is_acceptable`.

      recurse_sublayouts (optional): Whether delegated layouts are diagnosed
          recursively.

    Returns:
      A :class:`ChainDiagnosis`.

    """
    if max_format_version is None:
        max_format_version = in_toto.settings.PROVENANCE_MAX_FORMAT_VERSION
    if tolerant is None:
        tolerant = in_toto.settings.PROVENANCE_TOLERANT_MODE
    if proof_locations is None:
        proof_locations = {}

    if _depth > _MAX_NESTING:
        return ChainDiagnosis(
            verdict=ChainVerdict.UNVERIFIABLE,
            confidence=Confidence.NONE,
            root_error="Sublayout nesting exceeds the diagnosis depth limit",
            tolerant=tolerant,
        )

    # Verify the root layout's own signatures, reusing the regular metadata
    # verification implementation. A bad root makes every layer untrustworthy.
    if _verify_root and layout_keys:
        for key in layout_keys.values():
            try:
                metadata.verify_signature(key)
            except Exception as e:  # noqa: BLE001
                return ChainDiagnosis(
                    verdict=ChainVerdict.REJECTED,
                    confidence=Confidence.NONE,
                    root_error=(
                        "Root layout signature verification failed: "
                        f"{type(e).__name__}: {e}"
                    ),
                    tolerant=tolerant,
                )

    try:
        layout = metadata.get_payload()
    except Exception as e:  # noqa: BLE001
        return ChainDiagnosis(
            verdict=ChainVerdict.UNVERIFIABLE,
            confidence=Confidence.NONE,
            root_error=f"Root metadata payload cannot be parsed: {e}",
            tolerant=tolerant,
        )

    if not isinstance(layout, Layout):
        return ChainDiagnosis(
            verdict=ChainVerdict.UNVERIFIABLE,
            confidence=Confidence.NONE,
            root_error="Root metadata does not contain a layout",
            tolerant=tolerant,
        )

    if _verify_root:
        try:
            verify_layout_expiration(layout)
        except LayoutExpiredError as e:
            return ChainDiagnosis(
                verdict=ChainVerdict.REJECTED,
                confidence=Confidence.NONE,
                root_error=f"Root layout is expired: {e}",
                tolerant=tolerant,
            )

    layers = []
    previous_link = None
    previous_verified = True
    has_previous = False

    for index, step in enumerate(layout.steps):
        location = proof_locations.get(step.name, ProofLocation.AUTO)
        probe = _probe_layer(step, layout, link_dir_path, proof_store, location)

        if "status" in probe:
            layer = _terminal_layer(step, index, probe, layout)
            if has_previous and not previous_verified:
                layer.details["isolation"] = (
                    "A previous layer is not verified, so chain continuity is "
                    "unknown."
                )
            layers.append(layer)
            previous_link = None
            previous_verified = False
            has_previous = True
            continue

        docs, source_format, version, problem = _parse_proofs(
            probe["raw_docs"], max_format_version
        )
        if problem is not None:
            layer = _unverifiable_layer(
                step, index, probe, layout, problem[0], problem[1], version
            )
            layer.details["isolation"] = (
                "The proof cannot be interpreted, so chain continuity is "
                "unknown."
            )
            layers.append(layer)
            previous_link = None
            previous_verified = False
            has_previous = True
            continue

        layer = _diagnose_proof_layer(
            step,
            index,
            docs,
            probe,
            source_format,
            version,
            layout,
            link_dir_path,
            proof_store,
            proof_locations,
            artifact_base_path,
            max_format_version,
            tolerant,
            recurse_sublayouts,
            _depth,
        )

        current_link = None
        if layer.status is LayerStatus.VERIFIED:
            payload = docs[0].get_payload()
            if payload.type_ == "link":
                current_link = payload
            else:
                current_link = layer.details.get("_summary_source")

        if (
            layer.status is LayerStatus.VERIFIED
            and has_previous
            and previous_verified
            and previous_link is not None
            and current_link is not None
        ):
            cross_mismatches = _cross_layer_mismatches(
                previous_link, current_link
            )
            if cross_mismatches:
                layer.status = LayerStatus.TAMPERED
                layer.reason = (
                    "Signature(s) verify, but this layer's materials do not "
                    "match the previous layer's signed products."
                )
                layer.remediation = _REMEDIATION[LayerStatus.TAMPERED]
                layer.tamper_details = tuple(cross_mismatches)
                layer.confidence = Confidence.NONE
                current_link = None

        if layer.status is LayerStatus.VERIFIED:
            if current_link is not None:
                layer.details["_summary_source"] = current_link
            layer.continuity_verified = previous_verified or not has_previous
            if not layer.continuity_verified:
                layer.details["isolation"] = (
                    "The previous layer is not verified; this layer was "
                    "verified on its own, so chain continuity is unknown."
                )
            previous_link = current_link
            previous_verified = True
        else:
            layer.continuity_verified = False
            if has_previous:
                layer.details["isolation"] = (
                    "Chain continuity to the previous layer could not be "
                    "established; conclusions for this layer are local only."
                )
            previous_link = None
            previous_verified = False

        has_previous = True
        layers.append(layer)

    diagnosis = _summarize(layers, tolerant)
    diagnosis.summary_link = _summary_link(layers, "")
    return diagnosis
