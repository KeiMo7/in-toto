# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Module Name>
  path.py

<Purpose>
  Single place for artifact path normalization and path-aware pattern
  matching.

  Both artifact *recording* (see ``in_toto.resolver``) and artifact *rule
  matching* (see ``in_toto.verifylib``) must use the exact same normalized
  representation of a path, so that a manifest written on one machine can be
  validated against rules on another machine regardless of the directory
  separator, case sensitivity or path spelling used.

  Normalization is performed exactly once per artifact: the resulting
  ``NormalizedPath`` carries both the manifest key (the normalized, relative
  spelling) and the original spelling(s). Rule decisions are made solely on
  the normalized form; the original spelling is retained for humans.

  Security properties enforced here:

    * Paths containing ``..`` references that resolve outside of the
      explicitly given base directory are rejected (path escape).
    * Absolute paths are anchored to the same base directory; entries that
      point outside of it are reported separately and rejected.
    * Symbolic links are recorded by their *link name*; the link target is
      used only to read the file's hash. A link whose target leaves the base
      directory is rejected. Unreadable targets degrade to an explicitly
      marked entry instead of being skipped silently.
    * Distinct spellings that fold onto the same normalized key (mixed
      directory separators, case-only differences on case-insensitive file
      systems) are reported as conflicts; the batch is rejected instead of
      one spelling silently overwriting the other.
    * Prefix stripping applies at path segment boundaries only.
    * Wildcards in artifact rules never match across a directory separator.

"""

import fnmatch
import os

from in_toto.exceptions import (
    UNRESOLVED_SYMLINK_ALGO,
    UNRESOLVED_SYMLINK_MARKER,
    PathConflictError,
    PathEscapeError,
    PrefixError,
    SymlinkError,
)


def is_case_insensitive(path):
    """Return True if the file system at ``path`` is case-insensitive.

    The check is best-effort: if the probe cannot be performed (e.g. the path
    does not exist or is not writable) a case-sensitive file system is
    assumed.
    """
    try:
        probe = os.path.join(path, ".in_toto_case_probe")
        with open(probe, "w", encoding="utf8"):
            pass
        insensitive = os.path.exists(
            os.path.join(path, ".IN_TOTO_CASE_PROBE")
        )
        os.remove(probe)
        return insensitive
    except OSError:
        return False


def split_segments(path):
    """Split a forward-slash relative path into its non-empty segments."""
    return [seg for seg in path.replace("\\", "/").split("/") if seg not in ("", ".")]


def lstrip_segments(path, lstrip_paths):
    """Left-strip a configured prefix at path segment boundaries only.

    A prefix only matches when it consists of complete leading path
    segments. A sibling directory whose name merely starts with the same
    characters (e.g. prefix ``foo/`` versus directory ``foobar/``) is never
    stripped.
    """
    segments = split_segments(path)
    for prefix in lstrip_paths:
        prefix_segments = split_segments(prefix)
        if (
            len(segments) >= len(prefix_segments)
            and segments[: len(prefix_segments)] == prefix_segments
        ):
            return "/".join(segments[len(prefix_segments) :])
    return path.replace("\\", "/")


class NormalizedPath:
    """Result of normalizing one artifact path.

    Attributes:
      key: Normalized manifest key, relative to the base directory, using
          forward slashes. This is the only representation used for rule
          matching and the exact dict key stored in a manifest (plus an
          optional scheme prefix, which is handled by the resolver).
      original: The spelling as provided by the caller (without scheme
          prefix). Retained for human inspection.
      abs_path: Absolute location on disk used for hashing. It is never
          embedded in error messages outside of the base directory.
      is_absolute: Whether the original spelling was an absolute path.
      pre_strip_key: Manifest key before configured prefix stripping, or the
          final key when no stripping applied. Allows conflict handling to
          tell spelling collisions apart from prefix-induced collisions.
      unresolved: True if the path is a symbolic link whose target could not
          be read. The entry is still recorded (by link name) and flagged.
    """

    def __init__(  # noqa: PLR0913, PLR0917
        self,
        key,
        original,
        abs_path,
        is_absolute=False,
        pre_strip_key=None,
        unresolved=False,
    ):
        self.key = key
        self.original = original
        self.abs_path = abs_path
        self.is_absolute = is_absolute
        self.pre_strip_key = pre_strip_key if pre_strip_key is not None else key
        self.unresolved = unresolved

    def __repr__(self):
        return (
            f"NormalizedPath(key={self.key!r}, original={self.original!r}, "
            f"unresolved={self.unresolved})"
        )


class PathNormalizer:
    """Normalizes artifact paths against one explicit base directory.

    A normalizer instance is shared by all artifacts of a single recording
    batch, which allows it to detect conflicts (two spellings folding onto
    the same key) and to keep track of every original spelling per key.

    Arguments:
      base_path: Explicit base directory. It is resolved to an absolute path
          once at construction time and never falls back to the process'
          current working directory implicitly: callers that want the current
          directory must pass ``os.getcwd()`` themselves.
      lstrip_paths: Optional prefixes stripped from normalized keys. Stripping
          only happens at path segment boundaries.
      follow_symlink_dirs: Whether directory traversal descends into
          directories that are symbolic links.
      case_insensitive: Force case-insensitive identity semantics. When None
          (default) the file system at ``base_path`` is probed once.
    """

    def __init__(
        self,
        base_path,
        lstrip_paths=None,
        follow_symlink_dirs=False,
        case_insensitive=None,
    ):
        if not isinstance(base_path, str) or not base_path:
            raise ValueError("'base_path' must be a non-empty string")

        # Resolve the base once and explicitly. ``realpath`` also gives us a
        # stable anchor for symlink escape checks.
        self._base_path = os.path.realpath(base_path)
        if not os.path.isdir(self._base_path):
            raise OSError(f"base path is not a directory: {base_path}")

        self._lstrip_paths = list(lstrip_paths or [])
        for prefix in self._lstrip_paths:
            if not isinstance(prefix, str):
                raise TypeError("'lstrip_paths' must be a list of strings")

        self._follow_symlink_dirs = follow_symlink_dirs

        if case_insensitive is None:
            case_insensitive = is_case_insensitive(self._base_path)
        self._case_insensitive = case_insensitive

        # normalized identity key -> NormalizedPath (first spelling wins as
        # the manifest key, see ``register``)
        self._entries = {}
        # normalized identity key -> list of all original spellings seen
        self._spellings = {}
        # hard, batch-failing validation errors (base-relative messages)
        self._failures = []
        # parallel list of exception classes, one per hard failure
        self._failure_types = []
        # soft degradations: normalized keys of unreadable symlink targets
        self._unresolved = []

    @property
    def base_path(self):
        """Absolute, resolved base directory."""
        return self._base_path

    @property
    def failures(self):
        """List of human-readable, base-relative hard failure messages."""
        return list(self._failures)

    @property
    def unresolved_paths(self):
        """Normalized keys recorded with an unreadable symlink target."""
        return list(self._unresolved)

    @property
    def spellings(self):
        """Mapping of normalized manifest key to all original spellings.

        This is how a de-duplicated entry can still tell which spellings it
        came from (see requirement "去重后仍要能说出它来自哪几种写法").
        """
        return {
            self._entries[identity].key: list(spelling)
            for identity, spelling in self._spellings.items()
            if identity in self._entries
        }

    def _identity(self, normalized_rel):
        """Return the de-duplication identity of a normalized relative key."""
        if self._case_insensitive:
            return normalized_rel.lower()
        return normalized_rel

    def _is_within_base(self, abs_path):
        """True if ``abs_path`` is the base or inside of it."""
        try:
            common = os.path.commonpath([self._base_path, abs_path])
        except ValueError:
            # Different drives on Windows
            return False
        return common == self._base_path

    def _rel(self, abs_path):
        """Base-relative, forward-slash path for locatable, safe messages."""
        return os.path.relpath(abs_path, self._base_path).replace("\\", "/")

    def _fail(self, exc_type, message):
        """Record a hard failure with its exception type and raise it."""
        self._failures.append(message)
        self._failure_types.append(exc_type)
        return exc_type(message)

    def normalize(self, path, original=None):
        """Normalize one path against the base directory.

        The path is interpreted relative to the base directory (or anchored
        to it, if absolute). Paths that escape the base are recorded as
        failures and raise ``PathEscapeError``.

        Raises:
          PathEscapeError: the path resolves outside the base directory.
          SymlinkError: the path is a dangling or cyclic symbolic link.
        """
        if original is None:
            original = path

        is_absolute = os.path.isabs(path)
        abs_path = os.path.abspath(
            path if is_absolute else os.path.join(self._base_path, path)
        )

        # Reject parent-directory escapes before touching the file system.
        # ``abspath`` collapses any ``..`` / ``.`` segments; if the result is
        # not within the base, the entry tries to leave the allowed range.
        if not self._is_within_base(abs_path):
            message = (
                "path escapes the allowed base directory and is rejected: "
                f"{self._rel(abs_path)}"
            )
            raise self._fail(PathEscapeError, message)

        # Dangling or cyclic symbolic links get a locatable error instead of
        # being silently skipped. ``os.path.exists`` follows links and is
        # False for both missing targets and cycles.
        if os.path.islink(abs_path) and not os.path.exists(abs_path):
            rel_name = self._rel(abs_path)
            target = os.readlink(abs_path)
            target_abs = os.path.abspath(
                os.path.join(os.path.dirname(abs_path), target)
            )
            is_cycle = os.path.islink(target_abs) or (
                os.path.normpath(target_abs) == os.path.normpath(abs_path)
            )
            if is_cycle:
                message = f"symbolic link cycle detected at: {rel_name}"
            else:
                message = (
                    "symbolic link points to a non-existing target at: "
                    f"{rel_name}"
                )
            raise self._fail(SymlinkError, message)

        # Manifest key: base-relative, forward slashes, no "./" and no
        # redundant segments. Symbolic links keep their link name, because
        # the link itself is not resolved here.
        pre_strip_key = self._rel(abs_path)
        normalized = lstrip_segments(pre_strip_key, self._lstrip_paths)

        return NormalizedPath(
            key=normalized,
            original=original,
            abs_path=abs_path,
            is_absolute=is_absolute,
            pre_strip_key=pre_strip_key,
        )

    def register(self, normalized):
        """Register a normalized entry, detecting folding conflicts.

        Two kinds of folding are distinguished:

        * The normalized identity is claimed by more than one *spelling*
          (mixed directory separators, case-only differences on a
          case-insensitive file system): ``PathConflictError``. Every source
          spelling is retained and the batch must be rejected.
        * Two *different* on-disk entities end up with the same manifest key
          through prefix stripping, i.e. the spellings were already
          identical before stripping: :class:`~in_toto.exceptions.PrefixError`,
          preserving the historic contract of the lstrip feature.

        The first registered spelling remains the manifest key so that
        normal, single-spelling batches produce byte-identical results to
        previous versions.

        Raises:
          PathConflictError: different spellings claim the same identity.
          PrefixError: a different entity already claims this identity due
              to prefix stripping.
        """
        identity = self._identity(normalized.key)
        spellings = self._spellings.setdefault(identity, [])
        if normalized.original not in spellings:
            spellings.append(normalized.original)

        if identity in self._entries:
            existing = self._entries[identity]

            # Same spelling (up to case-insensitive identity) reaching the
            # same normalized key twice is idempotent, e.g. a duplicate URI.
            same_spelling = (
                os.path.normcase(existing.original)
                == os.path.normcase(normalized.original)
            )
            if same_spelling:
                return existing

            # Distinct pre-strip keys can only collide through prefix
            # stripping: that is the historic PrefixError contract.
            stripped_into_collision = self._identity(
                existing.pre_strip_key
            ) != self._identity(normalized.pre_strip_key)
            if stripped_into_collision:
                message = (
                    "prefix selection has resulted in a non unique manifest "
                    f"key '{normalized.key}'; source spellings: "
                    f"{sorted(spellings)}"
                )
                raise self._fail(PrefixError, message)

            # Otherwise distinct spellings fold onto one key by themselves
            # (mixed separators, case-only differences): a hard conflict.
            message = (
                "conflicting path spellings normalize to the same manifest "
                f"key '{normalized.key}'; source spellings: "
                f"{sorted(spellings)}"
            )
            raise self._fail(PathConflictError, message)

        self._entries[identity] = normalized
        return normalized

    def mark_unresolved(self, normalized):
        """Flag an entry whose symbolic link target cannot be hashed.

        This is a *soft* failure: recording continues, the entry keeps its
        link-name key and rule matching can see the marker afterwards.
        """
        identity = self._identity(normalized.key)
        entry = self._entries.get(identity)
        if entry is None:
            entry = self.register(normalized)
        entry.unresolved = True
        if entry.key not in self._unresolved:
            self._unresolved.append(entry.key)
        return entry

    def check_within_base(self, normalized):
        """Validate that the on-disk target stays within the base directory.

        Every recorded file is checked through its fully resolved path, so
        files reached via a followed symbolic-link directory cannot smuggle
        out-of-base content in under a link name. Symbolic links themselves
        keep their link name as the manifest key; only hash reading follows
        the target.

        Raises:
          PathEscapeError: the resolved target leaves the base directory.
        """
        real_target = os.path.realpath(normalized.abs_path)
        if not self._is_within_base(real_target):
            message = (
                f"symbolic link at '{self._rel(normalized.abs_path)}' points "
                "outside of the allowed base directory and is rejected"
            )
            raise self._fail(PathEscapeError, message)
        return True

    def entries(self):
        """Return all registered ``NormalizedPath`` objects."""
        return list(self._entries.values())

    def raise_if_failed(self):
        """Raise an aggregated error if any hard validation error occurred.

        Soft degradations (unresolved symlink targets) are not part of this
        failure set; they are reported through ``unresolved_paths`` and the
        marker in the manifest instead.
        """
        if self._failures:
            message = (
                "artifact path validation failed:\n - "
                + "\n - ".join(self._failures)
            )
            # Preserve the specific exception type when the whole batch
            # failed for one reason; otherwise raise the generic escape
            # error so callers cannot accidentally treat a mixed batch as a
            # single, narrower failure.
            unique_types = set(self._failure_types)
            if len(unique_types) == 1:
                raise next(iter(unique_types))(message)
            raise PathEscapeError(message)


def path_glob_filter(names, pattern):
    """Filter ``names`` by glob ``pattern`` without crossing directories.

    This replaces ``fnmatch.filter`` for artifact rule matching: a wildcard
    (``*``, ``?`` or a character class) must not match the directory
    separator ``/``, so that a rule limited to a sub-directory cannot allow
    deeper paths. Each path segment is matched independently and ``**`` is
    treated as an ordinary ``*`` within a segment (artifact rules use
    fnmatch-style patterns, not gitignore-style patterns).

    The comparison is case-sensitive, matching ``fnmatch.fnmatchcase``.
    """
    matched = []
    pattern_segments = pattern.split("/")
    for name in names:
        name_segments = name.split("/")
        if len(pattern_segments) != len(name_segments):
            continue
        if all(
            fnmatch.fnmatchcase(name_seg, pat_seg)
            for name_seg, pat_seg in zip(name_segments, pattern_segments)
        ):
            matched.append(name)
    return matched


def normalize_rule_path(path):
    """Normalize a path embedded in an artifact rule (prefix or pattern base).

    Rules originate from layouts and are matched against normalized manifest
    keys; hence their separators are normalized to forward slashes in the
    same shared module instead of being ad-hoc normalized at each call site.
    """
    return path.replace("\\", "/")


def strip_rule_prefix(path, prefix):
    """Strip a rule path prefix at segment boundaries.

    Returns the path with ``prefix`` removed, or None if the path does not
    start with the prefix at a complete path segment. Used by MATCH rules,
    where globbing must not be applied to the prefix itself.
    """
    path = normalize_rule_path(path)
    prefix = normalize_rule_prefix(prefix)
    if path.startswith(prefix):
        return path[len(prefix) :]
    return None


def normalize_rule_prefix(prefix):
    """Normalize a rule prefix to forward-slash form with a trailing slash."""
    prefix = normalize_rule_path(prefix)
    if not prefix.endswith("/"):
        prefix += "/"
    return prefix


def unresolved_hash_dict():
    """Hash-dict shaped marker for an unreadable symbolic link target.

    The value shape still passes the manifest's structural expectations
    (algorithm name -> string) while being unmistakably synthetic and visible
    to rule matching via ``is_unresolved_hash_dict``.
    """
    return {UNRESOLVED_SYMLINK_ALGO: UNRESOLVED_SYMLINK_MARKER}


def is_unresolved_hash_dict(hash_dict):
    """Return True if ``hash_dict`` flags an unresolved symbolic link."""
    return (
        isinstance(hash_dict, dict)
        and hash_dict.get(UNRESOLVED_SYMLINK_ALGO) == UNRESOLVED_SYMLINK_MARKER
    )
