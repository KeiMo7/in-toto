# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error

# Marker recorded in place of a hash dict when a symbolic link target cannot
# be read. Defined here (rather than in in_toto.path) to avoid import cycles
# between the format validators and the path normalizer.
UNRESOLVED_SYMLINK_MARKER = "in-toto:unresolved-symlink"
UNRESOLVED_SYMLINK_ALGO = "in-toto"


class SignatureVerificationError(Error):
    """Indicates a signature verification Error."""


class LayoutExpiredError(Error):
    """Indicates that the layout expired."""


class RuleVerificationError(Error):
    """Indicates that artifact rule verification failed."""


class ThresholdVerificationError(Error):
    """Indicates that signature threshold verification failed."""


class BadReturnValueError(Error):
    """Indicates that a ran command exited with non-int or non-zero return
    value."""


class LinkNotFoundError(Error):
    """Indicates that a link file was not found."""


class UnsupportedKeyTypeError(Error):
    """Indicates that the specified key type is not yet supported."""


class PrefixError(Error):
    """Indicates that there is an error because of the prefixes passed."""


class PathEscapeError(Error):
    """Indicates that a path escapes the explicitly allowed base directory.

    The message must not contain absolute path details outside of the base
    directory, see in_toto.path.PathNormalizer.
    """


class PathConflictError(Error):
    """Indicates that two or more distinct path spellings normalize to the
    same manifest key (e.g. mixed directory separators or case-insensitive
    file systems). The error lists all source spellings so that no arbitrary
    choice is made."""


class SymlinkError(Error):
    """Indicates that a symbolic link cannot be resolved, e.g. because it is
    part of a cycle or its target does not exist. The offending link is
    reported by its name relative to the base directory."""


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""
