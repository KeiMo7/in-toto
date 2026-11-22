# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  settings.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  A central place to define default settings that can be used throughout the
  package.

  Defaults can be changed,
   - here (hardcoded),
   - programmatically, e.g.
     ```
     import in_toto.settings
     in_toto.settings.ARTIFACT_BASE_PATH = "/home/user/project"
     ```
"""

# The debug setting is used to set to the in-toto base logger to logging.DEBUG
DEBUG = False

# See docstring of `in-toto.record_artifacts_as_dict` for how this is used
ARTIFACT_EXCLUDE_PATTERNS = ["*.link*", ".git", "*.pyc", "*~"]

# Used as base path for --materials and --products arguments when running
# in-toto-run/in-toto-record
# If not set the current working directory is used as base path
# FIXME: Do we want different base paths for materials and products?
ARTIFACT_BASE_PATH = None

# Max timeout for the in-toto-run command
LINK_CMD_EXEC_TIMEOUT = 10

# Highest provenance proof format version understood by the diagnostics engine.
# Proofs that declare a higher version are reported as "unverifiable" with an
# explicit upgrade recommendation, rather than as corrupt.
PROVENANCE_MAX_FORMAT_VERSION = 1

# Default for whether partial provenance verification may be accepted. This is
# only a default for callers that do not pass the option explicitly; the
# regular verification workflow always stays fail-closed.
PROVENANCE_TOLERANT_MODE = False
