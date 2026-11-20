# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared path normalization module and its integration with
artifact recording (resolver) and rule matching (verifylib).

These tests pin the security boundary requirements:

* parent-directory (``..``) escapes are rejected,
* absolute paths are anchored to one explicit base directory,
* symbolic links that leave the base are rejected while internal links keep
  their link name,
* dangling/cyclic links raise locatable errors,
* unreadable link targets degrade to an explicit marker,
* mixed separator or case-only spellings conflict instead of overwriting,
* rule wildcards never cross directory separators,
* prefix stripping only happens at segment boundaries,
* original spellings are retained next to the normalized manifest key.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from in_toto.exceptions import (
    PathConflictError,
    PathEscapeError,
    PrefixError,
    SymlinkError,
)
from in_toto.models.link import Link
from in_toto.path import (
    PathNormalizer,
    is_unresolved_hash_dict,
    lstrip_segments,
    normalize_rule_prefix,
    path_glob_filter,
    strip_rule_prefix,
    unresolved_hash_dict,
)
from in_toto.resolver import FileResolver
from in_toto.rulelib import unpack_rule
from in_toto.runlib import (
    get_last_artifact_spellings,
    record_artifacts_as_dict,
)
from in_toto.verifylib import verify_allow_rule, verify_match_rule
from tests.common import TmpDirMixin

SYMLINK_SUPPORTED = "symlink" in os.__dict__


class TestPathNormalizer(unittest.TestCase):
    """Direct unit tests for PathNormalizer."""

    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp())
        os.makedirs(os.path.join(self.base, "sub", "deep"))
        for rel in ("foo", "sub/bar", "sub/deep/x"):
            path = os.path.join(self.base, rel)
            with open(path, "w", encoding="utf8") as fp:
                fp.write(rel)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_base_path_required(self):
        """The base directory must be given explicitly, never defaulted."""
        with self.assertRaises(ValueError):
            PathNormalizer("")
        with self.assertRaises(ValueError):
            PathNormalizer(None)  # type: ignore[arg-type]

    def test_base_path_must_exist(self):
        with self.assertRaises(OSError):
            PathNormalizer(os.path.join(self.base, "does-not-exist"))

    def test_normal_relative_key_unchanged(self):
        """Normal relative paths keep their exact manifest key."""
        normalizer = PathNormalizer(self.base)
        normalized = normalizer.normalize("sub/bar")
        self.assertEqual(normalized.key, "sub/bar")
        self.assertEqual(normalized.original, "sub/bar")
        self.assertFalse(normalized.is_absolute)

    def test_dot_slash_normalized_away(self):
        normalizer = PathNormalizer(self.base)
        self.assertEqual(normalizer.normalize("./sub/bar").key, "sub/bar")

    def test_backslash_normalized_to_forward_slash(self):
        normalizer = PathNormalizer(self.base)
        normalized = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub\\bar"
        )
        self.assertEqual(normalized.key, "sub/bar")
        # The original spelling is retained verbatim for humans.
        self.assertEqual(normalized.original, "sub\\bar")

    def test_parent_directory_escape_rejected(self):
        """A ``..`` reference leaving the base fails and is locatable."""
        normalizer = PathNormalizer(self.base)
        with self.assertRaises(PathEscapeError) as ctx:
            normalizer.normalize("../evil")
        message = str(ctx.exception)
        self.assertIn("escapes", message)
        # No absolute path details outside the base leak into the message.
        self.assertNotIn(self.base, message)

    def test_absolute_outside_base_rejected(self):
        normalizer = PathNormalizer(self.base)
        outside = os.path.realpath(tempfile.mkstemp()[1])
        try:
            with self.assertRaises(PathEscapeError):
                normalizer.normalize(outside)
        finally:
            os.remove(outside)

    def test_absolute_inside_base_anchored(self):
        normalizer = PathNormalizer(self.base)
        normalized = normalizer.normalize(
            os.path.join(self.base, "sub", "bar")
        )
        self.assertEqual(normalized.key, "sub/bar")
        self.assertTrue(normalized.is_absolute)

    def test_mixed_separator_conflict(self):
        """Two separator spellings of one entity conflict, no overwrite."""
        normalizer = PathNormalizer(self.base)
        first = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub/bar"
        )
        second = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub\\bar"
        )
        normalizer.register(first)
        with self.assertRaises(PathConflictError) as ctx:
            normalizer.register(second)
        # Both source spellings must be listed in the error.
        message = str(ctx.exception)
        self.assertIn("sub/bar", message)
        self.assertIn("sub\\\\bar", message)

    def test_case_insensitive_conflict(self):
        """On case-insensitive semantics, case-only variants are one entity."""
        normalizer = PathNormalizer(self.base, case_insensitive=True)
        lower = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub/bar"
        )
        upper = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="SUB/BAR"
        )
        normalizer.register(lower)
        with self.assertRaises(PathConflictError):
            normalizer.register(upper)

    def test_duplicate_spelling_is_idempotent(self):
        normalizer = PathNormalizer(self.base)
        first = normalizer.normalize("sub/bar")
        second = normalizer.normalize("sub/bar")
        normalizer.register(first)
        # Same spelling twice does not raise and returns the same entry.
        self.assertIs(normalizer.register(second), first)

    def test_spellings_retained_after_dedup(self):
        """A de-duplicated entry still knows all its source spellings."""
        normalizer = PathNormalizer(self.base)
        first = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub/bar"
        )
        normalizer.register(first)
        # A second, distinct spelling raises, but spellings are retained.
        second = normalizer.normalize(
            os.path.join(self.base, "sub", "bar"), original="sub\\bar"
        )
        with self.assertRaises(PathConflictError):
            normalizer.register(second)
        self.assertEqual(
            normalizer.spellings["sub/bar"], ["sub/bar", "sub\\bar"]
        )

    def test_lstrip_segment_boundary(self):
        self.assertEqual(
            lstrip_segments("sub/bar", ["sub/"]), "bar"
        )
        # A sibling directory with a longer, shared prefix is not stripped.
        self.assertEqual(
            lstrip_segments("submarine/bar", ["sub/"]), "submarine/bar"
        )

    def test_lstrip_via_normalizer(self):
        normalizer = PathNormalizer(self.base, lstrip_paths=["sub/"])
        self.assertEqual(normalizer.normalize("sub/bar").key, "bar")
        self.assertEqual(
            normalizer.normalize("sub/deep/x").key, "deep/x"
        )

    def test_prefix_collision_is_prefix_error(self):
        """Two different files folded by prefix keep the historic error."""
        os.makedirs(os.path.join(self.base, "other"))
        with open(os.path.join(self.base, "other", "bar"), "w", encoding="utf8") as fp:
            fp.write("other")
        normalizer = PathNormalizer(
            self.base, lstrip_paths=["sub/", "other/"]
        )
        # Distinct files "sub/bar" and "other/bar" both strip to "bar".
        first = normalizer.normalize("sub/bar", original="sub/bar")
        second = normalizer.normalize("other/bar", original="other/bar")
        self.assertEqual(first.key, "bar")
        self.assertEqual(second.key, "bar")
        normalizer.register(first)
        with self.assertRaises(PrefixError):
            normalizer.register(second)

    def test_aggregated_failure_preserves_type(self):
        normalizer = PathNormalizer(self.base)
        with self.assertRaises(PathEscapeError):
            normalizer.normalize("../a")
        with self.assertRaises(PathEscapeError):
            normalizer.normalize("../b")
        with self.assertRaises(PathEscapeError):
            normalizer.raise_if_failed()


class TestSegmentGlob(unittest.TestCase):
    """Wildcards must not cross the directory separator."""

    def test_star_does_not_cross_separator(self):
        names = ["sub/bar", "sub/deep/x", "subfoo"]
        self.assertEqual(path_glob_filter(names, "sub/*"), ["sub/bar"])

    def test_star_matches_within_segment(self):
        self.assertEqual(
            path_glob_filter(["foo", "foobar", "bar"], "foo*"),
            ["foo", "foobar"],
        )

    def test_question_mark_does_not_cross_separator(self):
        # '?' matches exactly one character within a segment and cannot
        # consume the slash, so 'a/b' does not match 'a?b'.
        self.assertEqual(
            path_glob_filter(["a/b", "ab", "acb"], "a?b"), ["acb"]
        )

    def test_segment_count_must_match(self):
        self.assertEqual(
            path_glob_filter(["sub/bar", "sub/deep/x"], "sub/*"),
            ["sub/bar"],
        )
        self.assertEqual(
            path_glob_filter(["sub/deep/x"], "sub/*/*"), ["sub/deep/x"]
        )

    def test_case_sensitive(self):
        self.assertEqual(path_glob_filter(["Foo", "foo"], "foo"), ["foo"])

    def test_rule_prefix_segment_boundary(self):
        self.assertEqual(strip_rule_prefix("sub/bar", "sub"), "bar")
        # Sibling with a shared string prefix is not considered prefixed.
        self.assertIsNone(strip_rule_prefix("submarine/bar", "sub"))
        self.assertEqual(
            normalize_rule_prefix("sub\\"), "sub/"
        )


class TestResolverIntegration(TmpDirMixin, unittest.TestCase):
    """End-to-end checks through the FileResolver boundary."""

    def setUp(self):
        # Per-test isolated directory so symlinks and extra files created by
        # one test cannot leak into the manifest assertions of another.
        self.set_up_test_dir()
        Path("sub").mkdir()
        Path("sub/deep").mkdir()
        for name in ("foo", "sub/bar", "sub/deep/x"):
            Path(name).write_text(name, encoding="utf8")

    def tearDown(self):
        self.tear_down_test_dir()

    def test_normal_manifest_byte_shape(self):
        """Keys for normal relative paths stay exactly as before."""
        result = FileResolver().hash_artifacts(["."])
        self.assertEqual(
            sorted(result.keys()),
            ["foo", "sub/bar", "sub/deep/x"],
        )
        for hash_dict in result.values():
            self.assertIn("sha256", hash_dict)

    def test_parent_escape_fails_batch(self):
        with self.assertRaises(PathEscapeError):
            FileResolver().hash_artifacts(["../"])

    def test_absolute_outside_base_fails_batch(self):
        outside = os.path.realpath(tempfile.mkstemp()[1])
        try:
            with self.assertRaises(PathEscapeError):
                FileResolver().hash_artifacts([outside])
        finally:
            os.remove(outside)

    def test_absolute_inside_base_recorded_relative(self):
        inside = os.path.join(os.getcwd(), "sub", "bar")
        result = FileResolver().hash_artifacts([inside])
        self.assertEqual(list(result.keys()), ["sub/bar"])

    def test_original_spelling_preserved_in_conflict(self):
        resolver = FileResolver()
        normalizer = resolver._make_normalizer()
        first = normalizer.normalize(
            os.path.join(os.getcwd(), "sub", "bar"), original="sub/bar"
        )
        second = normalizer.normalize(
            os.path.join(os.getcwd(), "sub", "bar"), original="sub\\bar"
        )
        normalizer.register(first)
        with self.assertRaises(PathConflictError) as ctx:
            normalizer.register(second)
        self.assertIn("sub/bar", str(ctx.exception))
        self.assertIn("sub\\\\bar", str(ctx.exception))

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink not supported")
    def test_symlink_outside_base_rejected(self):
        outside_dir = os.path.realpath(tempfile.mkdtemp())
        try:
            outside_target = os.path.join(outside_dir, "secret")
            Path(outside_target).write_text("secret", encoding="utf8")
            os.symlink(outside_target, "sub/escape")
            with self.assertRaises(PathEscapeError) as ctx:
                FileResolver().hash_artifacts(["sub/escape"])
            message = str(ctx.exception)
            self.assertIn("sub/escape", message)
            # Never leak the out-of-base absolute target or base itself.
            self.assertNotIn(outside_dir, message)
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)
            if os.path.lexists("sub/escape"):
                os.unlink("sub/escape")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink not supported")
    def test_internal_symlink_keeps_link_name(self):
        os.symlink("bar", "sub/bar_link")
        try:
            result = FileResolver().hash_artifacts(
                ["sub/bar", "sub/bar_link"]
            )
            self.assertIn("sub/bar_link", result)
            self.assertEqual(
                result["sub/bar_link"], result["sub/bar"]
            )
        finally:
            os.unlink("sub/bar_link")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink not supported")
    def test_dangling_symlink_raises_locatable_error(self):
        os.symlink("does/not/exist", "sub/dangling")
        try:
            with self.assertRaises(SymlinkError) as ctx:
                FileResolver().hash_artifacts(["sub/dangling"])
            self.assertIn("sub/dangling", str(ctx.exception))
        finally:
            os.unlink("sub/dangling")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink not supported")
    def test_symlink_cycle_raises_locatable_error(self):
        os.symlink("b", "sub/a")
        os.symlink("a", "sub/b")
        try:
            with self.assertRaises(SymlinkError) as ctx:
                FileResolver().hash_artifacts(["sub/a"])
            self.assertIn("cycle", str(ctx.exception).lower())
        finally:
            for link in ("sub/a", "sub/b"):
                if os.path.lexists(link):
                    os.unlink(link)

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink not supported")
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root bypasses permissions")
    def test_unreadable_target_degrades_to_marker(self):
        os.symlink("bar", "sub/unreadable_link")
        os.chmod("sub/bar", 0)
        try:
            result = FileResolver().hash_artifacts(["sub/unreadable_link"])
            self.assertTrue(
                is_unresolved_hash_dict(result["sub/unreadable_link"])
            )
        finally:
            os.chmod("sub/bar", 0o644)
            os.unlink("sub/unreadable_link")

    def test_lstrip_sibling_prefix_not_stripped(self):
        Path("submarine").mkdir()
        Path("submarine/z").write_text("z", encoding="utf8")
        resolver = FileResolver(lstrip_paths=["sub/"])
        result = resolver.hash_artifacts(["submarine", "sub"])
        self.assertIn("submarine/z", result)
        self.assertIn("bar", result)

    def test_spelling_side_channel_retains_originals(self):
        """The manifest keeps normalized keys; spellings are exposed beside it."""
        result = record_artifacts_as_dict(["sub/bar"])
        # Manifest key is the normalized relative path, byte-for-byte.
        self.assertEqual(list(result.keys()), ["sub/bar"])
        # The side channel retains the original spelling.
        self.assertEqual(
            get_last_artifact_spellings()["sub/bar"], ["sub/bar"]
        )

    def test_batch_collects_multiple_failures(self):
        """One bad entry does not hide the others in the final report."""
        normalizer = FileResolver()._make_normalizer()
        for bad in ("../a", "../b"):
            with self.assertRaises(PathEscapeError):
                normalizer.normalize(bad)
        with self.assertRaises(PathEscapeError) as ctx:
            normalizer.raise_if_failed()
        message = str(ctx.exception)
        self.assertIn("../a", message)
        self.assertIn("../b", message)


class TestRuleMatchingBoundary(unittest.TestCase):
    """Rule matching uses the same normalization as recording."""

    def test_allow_wildcard_does_not_cross_directory(self):
        # A rule limited to the top level must not allow a deeper path.
        queue = {"foo", "sub/bar"}
        self.assertEqual(verify_allow_rule("*", queue), {"foo"})

    def test_allow_subdir_wildcard_does_not_allow_deeper(self):
        queue = {"sub/bar", "sub/deep/x"}
        # Only the direct child is allowed; the deeper path is not consumed.
        self.assertEqual(
            verify_allow_rule("sub/*", queue), {"sub/bar"}
        )

    def test_match_rule_wildcard_boundary(self):
        sha = {"sha256": "a" * 64}
        links = {
            "src": Link(
                name="src",
                materials={},
                products={
                    "sub/bar": sha,
                    "sub/deep/x": sha,
                },
            ),
            "dst": Link(
                name="dst",
                materials={
                    "bar": sha,
                    "deep/x": sha,
                },
                products={},
            ),
        }
        rule = unpack_rule(
            ["MATCH", "*", "IN", "sub", "WITH", "MATERIALS", "FROM", "dst"]
        )
        queue = {"sub/bar", "sub/deep/x"}
        consumed = verify_match_rule(
            rule, queue, links["src"].products, links
        )
        # Only the direct child sub/bar matches; sub/deep/x cannot escape
        # the sub-directory scope through the wildcard.
        self.assertEqual(consumed, {"sub/bar"})

    def test_unresolved_marker_never_matches(self):
        real = {"sha256": "a" * 64}
        links = {
            "src": Link(
                name="src",
                materials={},
                products={"link": unresolved_hash_dict()},
            ),
            "dst": Link(
                name="dst",
                materials={"link": real},
                products={},
            ),
        }
        rule = unpack_rule(
            ["MATCH", "link", "WITH", "MATERIALS", "FROM", "dst"]
        )
        consumed = verify_match_rule(
            rule, {"link"}, links["src"].products, links
        )
        self.assertEqual(consumed, set())

    def test_marker_predicate(self):
        self.assertTrue(is_unresolved_hash_dict(unresolved_hash_dict()))
        self.assertFalse(
            is_unresolved_hash_dict({"sha256": "a" * 64})
        )


if __name__ == "__main__":
    unittest.main()
