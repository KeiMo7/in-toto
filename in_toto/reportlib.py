# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  reportlib.py

<Purpose>
  Machine-consumable verification report (failure attribution) for
  ``in_toto.verifylib``.

  Verification decisions and the structured report are produced from the same
  code path (see ``verifylib``): whenever a verification stage makes a decision
  that used to only surface as an exception or a log line, it now also hands a
  structured :class:`VerificationFinding` to the active
  :class:`VerificationReport`. Log messages and exception behavior are not
  parsed to construct any of the data below.

  The public contract of this module is intentionally small and stable:

  * closed value domains (string constants) for the categorical fields
    :data:`RESULTS`, :data:`CATEGORIES`, :data:`STAGES`, :data:`ITEM_TYPES`
    and :data:`ARTIFACT_TYPES` -- free text never goes into an enum field;
  * :class:`VerificationFinding`, one attributed failure record;
  * :class:`VerificationReport`, the homogeneous container that is returned
    for both failing and passing verifications;
  * :func:`in_toto_verify_with_report` (re-exported from ``verifylib``),
    the report-producing verification entry point.

  A report never contains key material or file contents. Only stable
  identifiers (step/inspection names, keyids, artifact *paths*, rule tokens,
  counts and the closed enums) are recorded. Artifact hashes, key values,
  command stdout/stderr and link environments are deliberately excluded.
"""

import contextvars
import json
import logging

from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    LinkNotFoundError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)

LOG = logging.getLogger(__name__)

# Bumped on any incompatible change of the dictionary/JSON contract below.
SCHEMA_VERSION = "1.0"

# Maximum number of findings kept in a report.
MAX_FINDINGS = 1000

# Maximum nesting depth of sublayout reports merged into one report.
MAX_SUBLAYOUT_DEPTH = 32

# ---------------------------------------------------------------------------
# Closed value domains. These are the only legal values of enum fields.
# ---------------------------------------------------------------------------

# Overall verification result.
RESULTS = type("Results", (), {"PASSED": "passed", "FAILED": "failed"})()

# Explicit failure categories. Free text must never be assigned here.
#   material_missing        - a required link/material is absent
#   signature_threshold     - not enough valid signatures / links disagree
#   rule_failure            - an artifact rule did not pass
#   command_return_value    - an inspection command returned abnormally
#   unknown                 - a failure that could not be classified
CATEGORIES = type(
    "Categories",
    (),
    {
        "MATERIAL_MISSING": "material_missing",
        "SIGNATURE_THRESHOLD": "signature_threshold",
        "RULE_FAILURE": "rule_failure",
        "COMMAND_RETURN_VALUE": "command_return_value",
        "UNKNOWN": "unknown",
    },
)()

# Verification pipeline stages, in execution order.
STAGES = type(
    "Stages",
    (),
    {
        "LAYOUT_SIGNATURES": "layout_signatures",
        "LAYOUT_EXPIRATION": "layout_expiration",
        "PARAMETER_SUBSTITUTION": "parameter_substitution",
        "LINK_LOADING": "link_loading",
        "LINK_SIGNATURE_THRESHOLDS": "link_signature_thresholds",
        "SUBLAYOUT": "sublayout",
        "COMMAND_ALIGNMENT": "command_alignment",
        "THRESHOLD_CONSTRAINTS": "threshold_constraints",
        "STEP_RULES": "step_rules",
        "INSPECTION_EXECUTION": "inspection_execution",
        "INSPECTION_RULES": "inspection_rules",
        "UNKNOWN": "unknown",
    },
)()

# Kind of supply chain item a finding is about.
ITEM_TYPES = type(
    "ItemTypes",
    (),
    {
        "STEP": "step",
        "INSPECTION": "inspection",
        "LAYOUT": "layout",
        "UNKNOWN": "unknown",
    },
)()

# Kind of artifact rule list a rule finding is about.
ARTIFACT_TYPES = type(
    "ArtifactTypes",
    (),
    {
        "MATERIALS": "materials",
        "PRODUCTS": "products",
    },
)()

# Maps the in-toto exceptions to the closed failure category domain. This
# mapping is the single place where exception types become categories, so
# callers cannot smuggle free text into the category field.
_EXCEPTION_CATEGORIES = {
    LinkNotFoundError: CATEGORIES.MATERIAL_MISSING,
    ThresholdVerificationError: CATEGORIES.SIGNATURE_THRESHOLD,
    RuleVerificationError: CATEGORIES.RULE_FAILURE,
    BadReturnValueError: CATEGORIES.COMMAND_RETURN_VALUE,
    LayoutExpiredError: CATEGORIES.UNKNOWN,
    SignatureVerificationError: CATEGORIES.UNKNOWN,
}


def category_for_exception(exc):
    """Return the closed category constant for a verification exception.

    Unrecognized exceptions map to :data:`CATEGORIES.UNKNOWN`, they are never
    dropped.
    """
    return _EXCEPTION_CATEGORIES.get(type(exc), CATEGORIES.UNKNOWN)


# The currently active report (``None`` outside of a report verification).
_ACTIVE_REPORT = contextvars.ContextVar("in_toto_report", default=None)


def _safe_str(value):
    """Best-effort string conversion that never raises."""
    try:
        return str(value)
    except Exception as e:  # noqa: BLE001
        return f"<unrepresentable {type(value).__name__}: {e!r}>"


def _json_safe(value):
    """Coerce ``value`` into JSON-serializable data, deterministically.

    Sets become sorted lists, tuples become lists, everything else falls back
    to its string form. Keys/material are never hashes or file contents.
    """
    if isinstance(value, dict):
        return {
            _safe_str(k): _json_safe(v)
            for k, v in sorted(value.items(), key=lambda kv: _safe_str(kv[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted((_json_safe(v) for v in value), key=_safe_str)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return _safe_str(value)


class VerificationFinding:
    """One attributed, machine-consumable verification failure.

    All categorical fields use values from the closed domains above.
    ``expected`` and ``actual`` carry directly comparable values (numbers,
    strings or sorted lists of paths), never human interpretation.
    ``message`` is the only free-text field and is meant for humans.
    """

    def __init__(  # noqa: PLR0913
        self,
        category,
        stage,
        message,
        item_type=ITEM_TYPES.UNKNOWN,
        item_name=None,
        item_path=None,
        artifact_type=None,
        rule=None,
        rule_type=None,
        rule_index=None,
        expected=None,
        actual=None,
        detail=None,
    ):
        self.category = category
        self.stage = stage
        self.message = _safe_str(message)
        self.item_type = item_type
        self.item_name = item_name
        self.item_path = item_path
        self.artifact_type = artifact_type
        self.rule = list(rule) if rule is not None else None
        self.rule_type = rule_type
        self.rule_index = rule_index
        self.expected = expected
        self.actual = actual
        self.detail = detail if detail is not None else {}

    def to_dict(self):
        """Return the stable dictionary representation (fixed key order)."""
        return {
            "category": self.category,
            "stage": self.stage,
            "item_type": self.item_type,
            "item_name": self.item_name,
            "item_path": self.item_path,
            "artifact_type": self.artifact_type,
            "rule": self.rule,
            "rule_type": self.rule_type,
            "rule_index": self.rule_index,
            "expected": _json_safe(self.expected),
            "actual": _json_safe(self.actual),
            "detail": _json_safe(self.detail),
            "message": self.message,
        }


def _finding_sort_key(data):
    """Deterministic total ordering, independent of insertion order."""
    return (
        data["stage"] or "",
        data["item_path"] or "",
        data["item_name"] or "",
        data["artifact_type"] or "",
        -1 if data["rule_index"] is None else data["rule_index"],
        data["category"],
        data["message"],
    )


class VerificationReport:
    """Homogeneous structured result of one verification run.

    The same schema is produced on success (``result == "passed"`` and an
    empty ``findings`` list) and on failure, so downstream consumers only
    need one parsing path.
    """

    def __init__(self, max_findings=None):
        self.schema_version = SCHEMA_VERSION
        self.result = RESULTS.PASSED
        self.findings = []
        self.truncated = False
        # Read the module constant at construction time so tests (and future
        # configuration) can adjust the cap via ``reportlib.MAX_FINDINGS``.
        self.max_findings = (
            max_findings if max_findings is not None else MAX_FINDINGS
        )
        # Minimal degradation conclusion: if constructing the detailed
        # attribution itself fails, the stage that failed is still recorded
        # together with the original error chain.
        self.report_errors = []

    # -- record keeping ----------------------------------------------------

    def add_finding(self, finding):
        """Add one finding, enforcing the closed category domain and cap."""
        if not isinstance(finding, VerificationFinding):
            raise TypeError("expected a VerificationFinding")

        categories = {
            getattr(CATEGORIES, name)
            for name in dir(CATEGORIES)
            if not name.startswith("_")
        }
        if finding.category not in categories:
            # Never let free text reach the enum field.
            finding.category = CATEGORIES.UNKNOWN

        if len(self.findings) >= self.max_findings:
            self.truncated = True
            LOG.warning(
                "Verification report finding limit (%d) reached,"
                " further findings are truncated.",
                self.max_findings,
            )
            return

        self.findings.append(finding)
        self.result = RESULTS.FAILED

    def record_failure(self, stage, exc, **kwargs):
        """Record an exception encountered in a stage as a finding.

        Unclassifiable exceptions become :data:`CATEGORIES.UNKNOWN` and keep
        their original error chain in ``detail.error_chain``.
        """
        category = kwargs.pop("category", None) or category_for_exception(exc)
        detail = dict(kwargs.pop("detail", None) or {})
        detail["error_type"] = type(exc).__name__
        detail["error_chain"] = _error_chain(exc)
        message = kwargs.pop("message", None) or _safe_str(exc)
        finding = VerificationFinding(
            category=category,
            stage=stage,
            message=message,
            detail=detail,
            **kwargs,
        )
        self.add_finding(finding)

    def record_report_error(self, stage, exc):
        """Degradation hook: attribution construction itself failed.

        The report still carries the minimal conclusion of which stage failed
        and preserves the original error chain.
        """
        entry = {
            "stage": stage,
            "error_type": type(exc).__name__,
            "error_chain": _error_chain(exc),
        }
        self.report_errors.append(entry)
        LOG.warning(
            "Failed to construct verification finding for stage '%s': %s",
            stage,
            entry["error_chain"],
        )

    # -- sublayout support -------------------------------------------------

    def merge_sublayout(self, step_name, sub_report, depth=0):
        """Merge a sublayout report, prefixing every finding with its path."""
        if depth > MAX_SUBLAYOUT_DEPTH:
            self.record_report_error(
                STAGES.SUBLAYOUT,
                RuntimeError(
                    f"sublayout nesting exceeds depth {MAX_SUBLAYOUT_DEPTH}"
                ),
            )
            return
        for finding in sub_report.findings:
            data = finding.to_dict()
            data["item_path"] = _join_path(step_name, data.get("item_path"))
            data["item_name"] = finding.item_name
            data.setdefault("detail", {})
            data["detail"]["sublayout_root"] = step_name
            self._add_dict_finding(data)
        for report_error in sub_report.report_errors:
            merged_error = dict(report_error)
            merged_error["stage"] = STAGES.SUBLAYOUT
            merged_error["sublayout_root"] = step_name
            self.report_errors.append(merged_error)
        if sub_report.result == RESULTS.FAILED:
            self.result = RESULTS.FAILED
        if sub_report.truncated:
            self.truncated = True

    def _add_dict_finding(self, data):
        """Re-ingest an already serialized finding (used on sublayout merge)."""
        finding = VerificationFinding(
            category=data["category"],
            stage=data["stage"],
            message=data["message"],
            item_type=data["item_type"],
            item_name=data["item_name"],
            item_path=data["item_path"],
            artifact_type=data["artifact_type"],
            rule=data["rule"],
            rule_type=data["rule_type"],
            rule_index=data["rule_index"],
            expected=data["expected"],
            actual=data["actual"],
            detail=data["detail"],
        )
        self.add_finding(finding)

    # -- output ------------------------------------------------------------

    def to_dict(self):
        """Return the stable, JSON-serializable report dictionary."""
        serialized = [finding.to_dict() for finding in self.findings]
        serialized.sort(key=_finding_sort_key)
        return {
            "schema_version": self.schema_version,
            "result": self.result,
            "summary": {
                "finding_count": len(serialized),
                "truncated": self.truncated,
                "max_findings": self.max_findings,
                "categories": _count_by(serialized, "category"),
                "stages": _count_by(serialized, "stage"),
            },
            "findings": serialized,
            "report_errors": self.report_errors,
        }

    def to_json(self):
        """Return deterministic JSON text (sorted keys, stable separators)."""
        return json.dumps(
            self.to_dict(), indent=2, sort_keys=True, separators=(",", ": ")
        )


def _error_chain(exc):
    """Return the exception chain as a list of type/message strings."""
    chain = []
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(
            {
                "error_type": type(current).__name__,
                "message": _safe_str(current),
            }
        )
        current = current.__cause__ or current.__context__
    return chain


def _join_path(prefix, suffix):
    """Join outer step name and inner item path into a full step path."""
    if not suffix:
        return prefix
    return f"{prefix}.{suffix}"


def _count_by(records, key):
    """Closed-domain histogram used in the report summary."""
    counts = {}
    for record in records:
        value = record.get(key)
        if value is None:
            continue
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))
