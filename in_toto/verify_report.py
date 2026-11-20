# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  verify_report.py

<Purpose>
  Provides structured, deterministic verification results for multi-step
  in-toto supply chain verification.

  A report records one result per step (and inspection), including the number
  of distinct authorized signers that were found for a step, the number that
  are still missing, and the concrete reason for every failure.  Reasons are
  produced by the verification engine itself, not reconstructed from log
  output, so a report can always be traced back to the check that failed.

  Step results are ordered by their artifact dependency graph, not by the
  order in which steps happen to appear in the layout, and all collections in
  the report are sorted, making repeated verification of the same input
  byte-for-byte reproducible.
"""

from dataclasses import dataclass, field

# Item status values. "undetermined" is deliberately distinct from "failed":
# a check that could not be evaluated must never be reported as passed.
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_UNDETERMINED = "undetermined"

# Issue severity values. Only "error" issues make an item fail; "undetermined"
# issues make it undetermined, while "warning" issues do not affect the status.
SEVERITY_ERROR = "error"
SEVERITY_UNDETERMINED = "undetermined"
SEVERITY_WARNING = "warning"

# Issue categories. They name the concrete check that produced the issue.
CATEGORY_LAYOUT_SIGNATURE = "layout_signature"
CATEGORY_LAYOUT_EXPIRED = "layout_expired"
CATEGORY_METADATA_MISSING = "metadata_missing"
CATEGORY_METADATA_UNPARSEABLE = "metadata_unparseable"
CATEGORY_INSUFFICIENT_SIGNERS = "insufficient_signers"
CATEGORY_INCONSISTENT_ARTIFACTS = "inconsistent_artifacts"
CATEGORY_RULE_VIOLATION = "rule_violation"
CATEGORY_RULE_EVALUATION_ERROR = "rule_evaluation_error"
CATEGORY_SUBLAYOUT_FAILURE = "sublayout_failure"
CATEGORY_INSPECTION_FAILURE = "inspection_failure"
CATEGORY_INSPECTION_SKIPPED = "inspection_skipped"
CATEGORY_COMMAND_MISMATCH = "command_mismatch"
CATEGORY_ATTRIBUTION_ERROR = "attribution_error"


def exception_chain(exc, max_entries=10):
    """Return a JSON-serializable description of an exception and its causes.

    The ``__cause__``/``__context__`` links are followed, so that a minimal
    fallback attribution still carries the original error chain.
    """
    chain = []
    seen = set()
    current = exc
    while current is not None and len(chain) < max_entries:
        if id(current) in seen:
            break
        seen.add(id(current))
        chain.append({"type": type(current).__name__, "message": str(current)})
        current = current.__cause__ or current.__context__
    return chain


def _normalize(value):
    """Recursively convert a value into a deterministic, JSON-like form."""
    if isinstance(value, dict):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (set, frozenset)):
        return sorted(_normalize(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


@dataclass(frozen=True)
class VerificationIssue:
    """A single, attributable verification finding.

    Attributes:
      category: The concrete check that produced the issue, e.g.
          ``rule_violation`` or ``insufficient_signers``.
      message: Human readable description, using the message produced by the
          check itself.
      path: Full step path, from the root layout down to the item the issue
          belongs to.  A nested step ``compile`` inside a delegated step
          ``build`` has the path ``("build", "compile")``.
      severity: One of ``error``, ``undetermined`` or ``warning``.
      details: Structured, machine readable facts (counts, artifact paths,
          keyids, original exception chain, ...).
    """

    category: str
    message: str
    path: tuple = ()
    severity: str = SEVERITY_ERROR
    details: dict = field(default_factory=dict)

    @property
    def step(self):
        """Return the innermost step name of the issue path, if any."""
        return self.path[-1] if self.path else None

    def to_dict(self):
        """Return the deterministic dictionary representation of the issue."""
        return {
            "category": self.category,
            "details": _normalize(self.details),
            "message": self.message,
            "path": list(self.path),
            "severity": self.severity,
            "step": self.step,
        }


def make_issue(
    category,
    message,
    path=(),
    severity=SEVERITY_ERROR,
    details=None,
):
    """Build a :class:`VerificationIssue`, degrading safely on failure.

    If constructing the structured issue fails for any reason, a minimal
    usable issue is returned instead, carrying the original error chain.  A
    failed attribution must never mask (or turn into a pass) the underlying
    verification outcome.
    """
    try:
        return VerificationIssue(
            category=category,
            message=str(message),
            path=tuple(path),
            severity=severity,
            details=dict(details or {}),
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationIssue(
            category=CATEGORY_ATTRIBUTION_ERROR,
            message=f"{category}: {message}",
            path=tuple(path) if path else (),
            severity=SEVERITY_UNDETERMINED,
            details={
                "attribution_error": exception_chain(exc),
                "original_category": str(category),
            },
        )


@dataclass
class ItemResult:
    """The verification result of a single step or inspection."""

    name: str
    path: tuple
    kind: str = "step"
    issues: list = field(default_factory=list)
    sub_reports: list = field(default_factory=list)
    threshold: int = None
    satisfied_signers: int = None
    missing_signers: int = None
    found_metadata: int = None
    signer_keyids: tuple = ()
    status: str = STATUS_UNDETERMINED

    def add_issue(self, issue):
        """Add an issue to this item."""
        self.issues.append(issue)

    def get_or_add_child(self, name, kind="step"):
        """Return the nested report item named ``name``, creating it if absent."""
        for report in self.sub_reports:
            if report.name == name:
                return report
        child = ItemResult(name=name, path=(*self.path, name), kind=kind)
        self.sub_reports.append(child)
        return child

    def finalize(self):
        """Derive the item status from its issues and nested reports."""
        for report in self.sub_reports:
            report.finalize()

        statuses = [issue.severity for issue in self.issues]
        statuses.extend(report.status for report in self.sub_reports)

        if SEVERITY_ERROR in statuses or STATUS_FAILED in statuses:
            self.status = STATUS_FAILED
        elif (
            SEVERITY_UNDETERMINED in statuses or STATUS_UNDETERMINED in statuses
        ):
            self.status = STATUS_UNDETERMINED
        else:
            self.status = STATUS_PASSED
        return self.status

    @property
    def passed(self):
        """Return True if the item passed verification."""
        return self.status == STATUS_PASSED

    def iter_issues(self):
        """Yield this item's issues, including those of nested sublayouts."""
        yield from self.issues
        for report in self.sub_reports:
            yield from report.iter_issues()

    def to_dict(self):
        """Return the deterministic dictionary representation of the item."""
        return {
            "found_metadata": self.found_metadata,
            "issues": [issue.to_dict() for issue in self.issues],
            "kind": self.kind,
            "missing_signers": self.missing_signers,
            "name": self.name,
            "path": list(self.path),
            "satisfied_signers": self.satisfied_signers,
            "signer_keyids": list(self.signer_keyids),
            "status": self.status,
            "sub_reports": [report.to_dict() for report in self.sub_reports],
            "threshold": self.threshold,
        }

    def format_lines(self, indent):
        """Return the item as human readable, deterministic lines."""
        pad = "  " * indent
        signer_info = ""
        if self.threshold is not None:
            signer_info = (
                f" (signers: {self.satisfied_signers} satisfied,"
                f" {self.missing_signers} missing,"
                f" required {self.threshold})"
            )
        lines = [
            (
                f"{pad}{self.kind} '{'/'.join(self.path)}':"
                f" {self.status}{signer_info}"
            )
        ]
        lines.extend(
            f"{pad}  - [{issue.category}] {issue.message}"
            for issue in sorted(
                self.issues, key=lambda issue: (issue.category, issue.message)
            )
        )
        if self.sub_reports:
            lines.append(f"{pad}  nested report for '{'/'.join(self.path)}':")
            for report in self.sub_reports:
                lines.extend(report.format_lines(indent + 2))
        return lines


@dataclass
class VerificationReport:
    """A complete, deterministic result for verified supply chain items.

    Attributes:
      steps: Step results in artifact dependency order.
      inspections: Inspection results in layout declaration order.
      issues: Layout-level issues that do not belong to a single item.
      ordered_step_names: Step names in the resolved dependency order.
      complete: False if verification was interrupted before all checks ran.
      summary_link: The summary link produced by a passing verification.
    """

    steps: list = field(default_factory=list)
    inspections: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    ordered_step_names: list = field(default_factory=list)
    complete: bool = False
    summary_link: object = None

    @property
    def items(self):
        """Return all step and inspection results of this layout."""
        return list(self.steps) + list(self.inspections)

    def add_issue(self, issue):
        """Add a layout-level issue."""
        self.issues.append(issue)

    def finalize(self):
        """Derive the status of all items and of the overall report."""
        for item in self.items:
            item.finalize()
        return self.verdict

    def _all_item_statuses(self):
        return [item.status for item in self.items]

    @property
    def verdict(self):
        """Return ``passed``, ``failed`` or ``undetermined``."""
        statuses = self._all_item_statuses()
        statuses.extend(issue.severity for issue in self.issues)
        if STATUS_FAILED in statuses or SEVERITY_ERROR in statuses:
            return STATUS_FAILED
        if STATUS_UNDETERMINED in statuses or SEVERITY_UNDETERMINED in statuses:
            return STATUS_UNDETERMINED
        if not self.complete:
            return STATUS_UNDETERMINED
        return STATUS_PASSED

    @property
    def passed(self):
        """Return True if the report verdict is ``passed``."""
        return self.verdict == STATUS_PASSED

    @property
    def status(self):
        """Alias of :attr:`verdict`, so nested reports compose like items."""
        return self.verdict

    def iter_issues(self):
        """Yield all issues, including nested sublayout issues."""
        yield from self.issues
        for item in self.items:
            yield from item.iter_issues()

    def has_error(self):
        """Return True if any issue has error severity."""
        return any(
            issue.severity == SEVERITY_ERROR for issue in self.iter_issues()
        )

    def to_dict(self):
        """Return the deterministic dictionary representation of the report."""
        return {
            "complete": self.complete,
            "inspections": [item.to_dict() for item in self.inspections],
            "issues": [issue.to_dict() for issue in self.issues],
            "ordered_step_names": list(self.ordered_step_names),
            "steps": [item.to_dict() for item in self.steps],
            "verdict": self.verdict,
        }

    def format_lines(self, indent=0):
        """Return the report as human readable, deterministic lines."""
        pad = "  " * indent
        lines = [f"{pad}verification: {self.verdict}"]
        if self.ordered_step_names:
            lines.append(
                f"{pad}ordered steps: {', '.join(self.ordered_step_names)}"
            )
        lines.extend(
            f"{pad}- [{issue.category}] {issue.message}"
            for issue in sorted(
                self.issues, key=lambda issue: (issue.category, issue.message)
            )
        )
        for item in self.items:
            lines.extend(item.format_lines(indent))
        return lines

    def format(self):
        """Return a human readable, deterministic multi-line summary."""
        return "\n".join(self.format_lines())

    def __str__(self):
        return self.format()
