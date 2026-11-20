# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error, FormatError


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


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""


class LayoutReferenceError(FormatError):
    """Indicates that a layout's step references are malformed.

    Raised before verification starts if a rule references a step that does
    not exist in the layout, or if step references form a dependency cycle.
    Inherits from ``securesystemslib.exceptions.FormatError`` so callers that
    already treat malformed layouts as format errors keep working.
    """

    def __init__(self, message, step=None, reference=None, cycle=None):
        super().__init__(message)
        self.step = step
        self.reference = reference
        self.cycle = tuple(cycle) if cycle else None
