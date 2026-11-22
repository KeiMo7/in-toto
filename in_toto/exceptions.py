# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error


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


class ProofStoreError(Error):
    """Base class for errors raised while fetching provenance proofs."""


class ProofStoreUnavailable(ProofStoreError):
    """Indicates that a proof store could not be reached.

    This is a transient/degraded condition and must not be confused with a
    proof that is absent from a reachable store. Callers are expected to retry
    before drawing conclusions about the proof itself.
    """


class ProofStoreTimeout(ProofStoreUnavailable):
    """Indicates that fetching a proof from a store timed out."""
