# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Provides a library to verify an in-toto final product containing
  a software supply chain layout.

  Take a look at `in_toto_verify`'s docstring for more details about the
  entire verification workflow.

"""

import datetime
import fnmatch
import logging
import os

import iso8601
import securesystemslib.exceptions
import securesystemslib.formats
from dateutil import tz
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.formats
import in_toto.models.layout
import in_toto.models.link
import in_toto.rulelib
import in_toto.runlib
import in_toto.settings
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    LayoutReferenceError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.formats import _check_parameter_dict, _check_public_keys
from in_toto.models.metadata import Metadata
from in_toto.verify_report import (
    CATEGORY_COMMAND_MISMATCH,
    CATEGORY_INCONSISTENT_ARTIFACTS,
    CATEGORY_INSPECTION_FAILURE,
    CATEGORY_INSPECTION_SKIPPED,
    CATEGORY_INSUFFICIENT_SIGNERS,
    CATEGORY_LAYOUT_EXPIRED,
    CATEGORY_LAYOUT_SIGNATURE,
    CATEGORY_METADATA_MISSING,
    CATEGORY_METADATA_UNPARSEABLE,
    CATEGORY_RULE_EVALUATION_ERROR,
    CATEGORY_RULE_VIOLATION,
    CATEGORY_SUBLAYOUT_FAILURE,
    SEVERITY_UNDETERMINED,
    SEVERITY_WARNING,
    ItemResult,
    VerificationReport,
    exception_chain,
    make_issue,
)

# A step whose *evidence* is not trustworthy cannot provide artifact evidence
# to other steps. These categories mean the link metadata itself could not be
# authenticated or read, as opposed to authentic metadata that violates a rule.
TRUST_FAILURE_CATEGORIES = {
    CATEGORY_INSUFFICIENT_SIGNERS,
    CATEGORY_LAYOUT_EXPIRED,
    CATEGORY_LAYOUT_SIGNATURE,
    CATEGORY_METADATA_MISSING,
    CATEGORY_METADATA_UNPARSEABLE,
    CATEGORY_SUBLAYOUT_FAILURE,
}

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

RULE_TRACE = {}


def _has_trust_failure(item):
    """Return True if an item's evidence could not be authenticated or read."""
    return any(
        issue.category in TRUST_FAILURE_CATEGORIES
        for issue in item.iter_issues()
    )


def _iter_step_dependency_names(step, layout):
    """Yield the names of the steps that ``step``'s MATCH rules reference."""
    step_names = {other.name for other in layout.steps}
    for _rule, dest_name in _iter_rule_references(step):
        if dest_name in step_names and dest_name != step.name:
            yield dest_name


def _item_report_scope(item):
    """Return a report container whose only known item is ``item``.

    ``verify_all_item_rules`` looks up item results by name. Wrapping a single
    item ensures findings are attributed to exactly that item (and, for
    inspections, not confused with a step of the same name).
    """

    class _ItemScope:
        def __init__(self, known):
            self._known = known
            self.items = [known]

        def get_or_add_child(self, name, kind="step"):  # noqa: ARG002
            return self._known

        def add_issue(self, issue):
            self._known.add_issue(issue)

    return _ItemScope(item)


def _find_item(container, name):
    """Find an ItemResult by name in a report or in an item's nested reports."""
    if isinstance(container, VerificationReport):
        candidates = container.items
    elif isinstance(container, ItemResult):
        candidates = container.sub_reports
    else:  # pragma: no cover (programming error)
        candidates = []

    for item in candidates:
        if item.name == name:
            return item
    return None


def _add_item_issue(container, name, issue):
    """Attribute an issue to the item named ``name``.

    If the item is not known, the issue is added to the container itself (for
    an ItemResult) or to the report's layout-level issues, so that no finding
    is silently dropped.
    """
    item = _find_item(container, name)
    if item is not None:
        item.add_issue(issue)
    else:
        container.add_issue(issue)


def _raise_on_bad_retval(return_value, command=None):
    """
    <Purpose>
      Internal function that checks return values of shell commands, e.g. from
      inspections. Raises exception if the passed value is non-int and non-zero.

    <Arguments>
      return_value:
              The return value to be verified
      command: (optional)
              The command whose execution returned the value, used for exception
              message.

    <Exceptions>
      BadReturnValueError if the return_value is non-int and non-zero

    <Side Effects>
      None.

    <Returns>
      None.
    """

    msg = "Got non-{what} " + f"return value '{return_value}'"
    if command:  # noqa: SIM108
        msg = f"{msg} from command '{command}'."
    else:
        msg = f"{msg}."

    if not isinstance(return_value, int):
        raise BadReturnValueError(msg.format(what="int"))

    # TODO: in-toto specification suggests special behavior on
    # return_value == 127, but does not fully define that behavior yet

    if return_value != 0:
        raise BadReturnValueError(msg.format(what="zero"))


def _iter_rule_references(item):
    """Yield ``(rule, dest_name)`` for every MATCH rule of a step/inspection."""
    for rules in (item.expected_materials, item.expected_products):
        for rule in rules:
            rule_data = in_toto.rulelib.unpack_rule(rule)
            if rule_data["rule_type"] == "match":
                yield rule, rule_data["dest_name"]


def get_step_dependencies(layout):
    """Return, per step, the set of step names its rules reference.

    Only MATCH rules create material flow between steps. Inspections are not
    dependency graph nodes, because they are executed after all steps and can
    reference any of them.
    """
    step_names = {step.name for step in layout.steps}
    dependencies = {step.name: set() for step in layout.steps}

    for step in layout.steps:
        for _rule, dest_name in _iter_rule_references(step):
            if dest_name in step_names and dest_name != step.name:
                dependencies[step.name].add(dest_name)

    return dependencies


def _validate_step_references(layout):
    """Reject malformed artifact-rule references before verification starts.

    Raises:
      LayoutReferenceError: A rule references an item that does not exist in
          the layout (a rule can reference a step, or an inspection), or step
          references form a cycle. The exception names the offending item,
          rule and, for cycles, the cycle's step path.

    Returns:
      The step dependency graph as returned by ``get_step_dependencies``.

    """
    step_names = {step.name for step in layout.steps}
    item_names = step_names | {inspection.name for inspection in layout.inspect}
    dependencies = get_step_dependencies(layout)

    for step in layout.steps:
        for rule, dest_name in _iter_rule_references(step):
            if dest_name != step.name and dest_name not in item_names:
                raise LayoutReferenceError(
                    f"Step '{step.name}' references unknown step"
                    f" '{dest_name}' in rule '{' '.join(rule)}'.",
                    step=step.name,
                    reference=dest_name,
                )

    for inspection in layout.inspect:
        for rule, dest_name in _iter_rule_references(inspection):
            if dest_name not in item_names:
                raise LayoutReferenceError(
                    f"Inspection '{inspection.name}' references unknown"
                    f" step '{dest_name}' in rule '{' '.join(rule)}'.",
                    step=inspection.name,
                    reference=dest_name,
                )

    ordered = _topological_order(dependencies)
    if ordered is None:
        cycle = _find_cycle(dependencies)
        cycle_str = " -> ".join(cycle)
        raise LayoutReferenceError(
            "Step references form a cycle: "
            f"{cycle_str}. Step order must be derived from artifact"
            " dependencies, which requires an acyclic graph.",
            step=cycle[0],
            reference=cycle[-1],
            cycle=cycle,
        )

    return dependencies


def _find_cycle(dependencies):
    """Return one cycle in a step dependency graph as a list of step names.

    The returned list starts and ends with the same step name. Only called
    when the graph is known to contain a cycle.
    """
    # Deterministic DFS: visit steps and their dependencies in sorted order.
    visited = set()
    stack = []
    on_stack = set()

    def visit(node):
        visited.add(node)
        stack.append(node)
        on_stack.add(node)
        for dependency in sorted(dependencies.get(node, ())):
            if dependency not in visited:
                cycle = visit(dependency)
                if cycle:
                    return cycle
            elif dependency in on_stack:
                start = stack.index(dependency)
                return [*stack[start:], dependency]
        stack.pop()
        on_stack.discard(node)
        return None

    for node in sorted(dependencies):
        if node not in visited:
            cycle = visit(node)
            if cycle:
                return cycle
    return []  # pragma: no cover (caller only invokes on cyclical graphs)


def _topological_order(dependencies):
    """Return step names in deterministic dependency order, or None on cycles.

    The order is derived solely from artifact dependencies. Steps that are
    independent of each other (including steps with no connections) are
    ordered by name, so neither layout order, directory traversal order nor
    hash order can influence the result. Dependencies are listed before their
    dependents.
    """
    remaining = {name: set(deps) for name, deps in dependencies.items()}
    ordered = []

    while remaining:
        ready = sorted(name for name, deps in remaining.items() if not deps)
        if not ready:
            return None
        # Emit all currently unblocked steps, then remove them from the graph.
        ordered.extend(ready)
        for name in ready:
            del remaining[name]
        for deps in remaining.values():
            deps.difference_update(ready)

    return ordered


def verify_step_order(layout):
    """Return step names in dependency order, validating references first.

    Raises:
      LayoutReferenceError: See ``_validate_step_references``.

    """
    return _topological_order(_validate_step_references(layout))


def load_links_for_layout(
    layout, link_dir_path, report=None, step_paths=None, raise_on_missing=True
):
    """
    <Purpose>
      Try to load all existing metadata files for each Step of the Layout
      from the current directory.

      For each step the metadata might consist of multiple (thresholds) Link
      or Layout (sub-layouts) files.

    <Arguments>
      layout:
            Layout object

      link_dir_path:
            A path to directory where links are loaded from

      report: (optional)
            A VerificationReport (or ItemResult for a sublayout) to which
            missing and unparseable metadata findings are attributed. If
            passed, unparseable metadata is skipped and recorded as a failure
            of the step instead of aborting the whole batch.

      step_paths: (optional)
            A mapping of step name to full report path, used to attribute
            findings to nested steps.

      raise_on_missing: (optional)
            If True (default), raise LinkNotFoundError on a preliminary
            threshold violation, preserving the historical behaviour.
            Report-driven verification passes False and records the finding
            instead, so that all steps still get an independent result.

    <Side Effects>
      Calls function to read files from disk

    <Exceptions>
      in_toto.exceptions.LinkNotFoundError,
              if fewer than `threshold` link files can be found for any given
              step of the supply chain (preliminary threshold check), and
              `raise_on_missing` is True.

    <Returns>
      A dictionary carrying all the found metadata corresponding to the
      passed layout, e.g.:

      {
        <step name> : {
          <functionary key id> : <Metadata containing a Link or Layout object>,
          ...
        }, ...
      }


    """
    steps_metadata = {}
    step_paths = step_paths or {}

    # Iterate over all the steps in the layout
    for step in layout.steps:
        links_per_step = {}

        # We try to load a link for every authorized functionary, but don't fail
        # if the file does not exist (authorized != required)
        # FIXME: Should we really pass on IOError, or just skip inexistent links?
        for authorized_keyid in step.pubkeys:
            # Iterate over the authorized key and if present over subkeys
            for keyid in [authorized_keyid] + list(
                layout.keys.get(authorized_keyid, {}).get("subkeys", {}).keys()
            ):
                filename = in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                )
                filepath = os.path.join(link_dir_path, filename)

                try:
                    metadata = Metadata.load(filepath)
                    links_per_step[keyid] = metadata

                except OSError:
                    pass

                except Exception as exc:
                    # Without a report, preserve the historical behaviour and
                    # propagate malformed metadata. With a report, unparseable
                    # metadata is not fatal for the whole batch, but it is a
                    # failure of this step and must be reported as such.
                    if report is None:
                        raise
                    LOG.warning(
                        "Skipping unparseable link metadata for step '%s'"
                        " (keyid '%s'): %s",
                        step.name,
                        keyid,
                        exc,
                    )
                    _add_item_issue(
                        report,
                        step.name,
                        make_issue(
                            CATEGORY_METADATA_UNPARSEABLE,
                            f"Could not parse link metadata '{filename}':"
                            f" {exc}",
                            path=step_paths.get(step.name, (step.name,)),
                            details={
                                "filename": filename,
                                "keyid": keyid,
                                "error": exception_chain(exc),
                            },
                        ),
                    )

        # This is only a preliminary threshold check, based on (authorized)
        # filenames, to fail early. A more thorough signature-based threshold
        # check is indispensable.
        if len(links_per_step) < step.threshold:
            message = (
                f"Step '{step.name}' requires '{step.threshold}'"
                f" link metadata file(s), found '{len(links_per_step)}'."
            )
            if raise_on_missing:
                raise in_toto.exceptions.LinkNotFoundError(message)

            # Distinguish "no information at all" from "not enough signers":
            # only the former is undetermined here. If some metadata exists,
            # signature threshold verification reports the concrete signer
            # deficit (satisfied/missing counts) as a failure.
            if report is not None and len(links_per_step) == 0:
                _add_item_issue(
                    report,
                    step.name,
                    make_issue(
                        CATEGORY_METADATA_MISSING,
                        message
                        + " No link metadata was found, so this step cannot"
                        " be evaluated.",
                        path=step_paths.get(step.name, (step.name,)),
                        severity=SEVERITY_UNDETERMINED,
                        details={
                            "found": len(links_per_step),
                            "required": step.threshold,
                        },
                    ),
                )

        steps_metadata[step.name] = links_per_step

    return steps_metadata


def run_all_inspections(
    layout,
    persist_inspection_links,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """
    <Purpose>
      Extracts all inspections from a passed Layout's inspect field and
      iteratively runs each command defined in the Inspection's `run` field using
      `runlib.in_toto_run`, which returns a Link object.

      If a link command returns non-zero the verification is aborted.

    <Arguments>
      layout:
              A Layout object which is used to extract the Inspections.

      persist_inspection_links:
              A boolean indicating whether link metadata files for inspection
              are written to cwd.

      timeout:
              Integer that is the amount of seconds that the inspection run will
              fail after.

    <Exceptions>
      Calls function that raises BadReturnValueError if an inspection returned
      non-int or non-zero.

    <Returns>
      A dictionary of metadata about the executed inspections, e.g.:

      {
        <inspection name> : {
          <Link object>,
          ...
        }, ...
      }

    """
    inspection_links_dict = {}
    for inspection in layout.inspect:
        LOG.info("Executing command for inspection '%s'...", inspection.name)

        # FIXME: We don't want to use the base path for runlib so we patch this
        # for now. This will not stay!
        base_path_backup = in_toto.settings.ARTIFACT_BASE_PATH
        in_toto.settings.ARTIFACT_BASE_PATH = None

        # FIXME: What should we record as material/product?
        # Is the current directory a sensible default? In general?
        # If so, we should probably make it a default in run_link
        # We could use artifact rule paths.
        material_list = product_list = ["."]
        link = in_toto.runlib.in_toto_run(
            inspection.name,
            material_list,
            product_list,
            inspection.run,
            timeout=timeout,
        )

        _raise_on_bad_retval(
            link.signed.byproducts.get("return-value"), inspection.run
        )

        inspection_links_dict[inspection.name] = link.signed

        # If client requests persistent inspection links,
        # Dump the inspection link file for auditing
        # Keep in mind that this pollutes the verifier's (client's) filesystem.
        if persist_inspection_links:
            filename = in_toto.models.link.FILENAME_FORMAT_SHORT.format(
                step_name=inspection.name
            )
            link.dump(filename)

        in_toto.settings.ARTIFACT_BASE_PATH = base_path_backup

    return inspection_links_dict


def verify_layout_expiration(layout):
    """
    <Purpose>
      Raises an exception if the passed layout has expired, i.e. if its
      `expires` property is lesser "now".
      Time zone aware datetime objects in UTC+00:00 (Zulu Time) are used.

    <Arguments>
      layout:
              The Layout object to be verified.

    <Exceptions>
      LayoutExpiredError
      TBA (see https://github.com/in-toto/in-toto/issues/6)

    <Side Effects>
      None.

    """
    expire_datetime = iso8601.parse_date(layout.expires)
    if expire_datetime <= datetime.datetime.now(tz.tzutc()):
        raise LayoutExpiredError("Layout expired")


def substitute_parameters(layout, parameter_dictionary):
    """
    <Purpose>
      This function is a transitionary measure for parameter substitution (or
      any other solution defined by the in-toto team). As of now, it acts as
      a very simple replacement layer for python-like parameters

    <Arguments>
      layout:
              The Layout object to process.

        parameter_dictionary:
              A dictionary containing key-value pairs for substitution.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        if the parameter dictionary is malformed.

      KeyError:
        if one of the keys in the parameter dictionary are not present for
        substitution

    <Side Effects>
      The layout object will have any tags replaced with the corresponding
      values defined in the parameter dictionary.
    """
    _check_parameter_dict(parameter_dictionary)

    for step in layout.steps:
        new_material_rules = []
        for rule in step.expected_materials:
            new_rule = [
                stanza.format(**parameter_dictionary) for stanza in rule
            ]
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in step.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_expected_command = [
            argv.format(**parameter_dictionary)
            for argv in step.expected_command
        ]

        step.expected_command = new_expected_command
        step.expected_materials = new_material_rules
        step.expected_products = new_product_rules

    for inspection in layout.inspect:
        new_material_rules = []
        for rule in inspection.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in inspection.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_run = [
            argv.format(**parameter_dictionary) for argv in inspection.run
        ]

        inspection.run = new_run
        inspection.expected_materials = new_material_rules
        inspection.expected_products = new_product_rules


def verify_metadata_signatures(metadata, keys_dict):
    """
    <Purpose>
      Iteratively verifies the signatures of a Metadata object containing
      a Layout object for every verification key in the passed keys dictionary.

      Requires at least one key to be passed and requires every passed key to
      find a valid signature.

    <Arguments>
      metadata:
              A Metadata object containing a Layout whose signatures are
              verified.

      keys_dict:
              A dictionary of keys to verify the signatures.

    <Exceptions>
      securesystemslib.exceptions.FormatError
        if the passed key dict is invalid.

      SignatureVerificationError
        if an empty verification key dictionary was passed, or
        if any of the passed verification keys fails to verify a signature.

      securesystemslib._gpg.exceptions.KeyExpirationError:
        if any of the passed verification keys is an expired gpg key

    """
    _check_public_keys(keys_dict)

    # Fail if an empty verification key dictionary was passed
    if len(keys_dict) < 1:
        raise SignatureVerificationError(
            "Layout signature verification requires at least one key."
        )

    # Fail if any of the passed keys can't verify a signature on the Layout
    for verify_key in keys_dict.values():
        metadata.verify_signature(verify_key)


def verify_link_signature_thresholds(  # noqa: C901, PLR0912, PLR0915
    layout, steps_metadata, report=None, step_paths=None
):
    """
    <Purpose>
      Verify that for each step of the layout there are at least `threshold`
      links metadata, signed by different authorized functionaries and return the
      verified link metadata dictionary containing only authorized links metadata
      whose signatures were successfully verified.

      NOTE: If the layout's key store (`layout.keys`) lists a (master) key `K`,
      with a subkey `K'`, then `K'` is authorized implicitly, to sign any link
      that `K` is authorized to sign. In other words, the trust in a master key
      extends to the trust in a subkey. The inverse is not true.

      NOTE: A threshold always counts distinct signers, not distinct keys or
      files. Links signed by a master key and by one or more of its subkeys
      count as one signer.

    <Arguments>
      layout:
              A Layout object whose Steps are extracted and verified.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                          object>,
                  ...
                }, ...
              }

      report: (optional)
              A VerificationReport (or ItemResult for a sublayout). If passed,
              threshold violations are recorded per step, together with the
              number of satisfied signers and the number of missing signers,
              and verification continues with the remaining steps instead of
              raising on the first violation.

      step_paths: (optional)
              A mapping of step name to full report path, used to attribute
              findings to nested steps.

    <Exceptions>
      ThresholdVerificationError
              If any of the steps of the passed layout does not have enough
              (`step.threshold`) links signed by different authorized
              functionaries. Only raised if no `report` is passed.

    <Returns>
      A steps_metadata containing only links with valid signatures created by
      authorized functionaries.

    """
    # pylint: disable=too-many-locals

    step_paths = step_paths or {}

    # Create an inverse keys-subkeys dictionary, with subkey keyids as
    # dictionary keys and main keys as dictionary values. This will be
    # required below to assess main-subkey trust delegations.
    # We assume that a given subkey can only belong to one master key
    # TODO: Is this a safe assumption? Should we assert for it?
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key

    # Dict for valid and authorized links of all steps of the layout
    verified_steps_metadata = {}

    # For each step of the layout check the signatures of corresponding links.
    # Consider only links where the signature is valid and keys are authorized,
    # and discard others.
    # Only count one of multiple links signed with different subkeys of a main
    # key towards link threshold.
    # Only proceed with final product verification if threshold requirements are
    # fulfilled.
    for step in layout.steps:
        # Dict for valid and authorized links of a given step
        verified_key_link_dict = {}
        # List of used signers, identified by their main keyid. Iterate over
        # sorted link keyids so the reported signer list does not depend on
        # dictionary insertion or hash order.
        used_main_keyids = []

        step_metadata = steps_metadata.get(step.name, {})

        # Do per step link threshold verification
        for link_keyid in sorted(step_metadata):
            link = step_metadata[link_keyid]
            try:
                link.get_payload()
            except Exception:  # noqa: BLE001
                # Malformed payloads were already recorded when loading.
                LOG.info(
                    "Skipping link with unparseable payload for step '%s'"
                    " (keyid '%s').",
                    step.name,
                    link_keyid,
                )
                continue

            # Iterate over authorized keyids to find a key or subkey corresponding
            # to the given link and check if the link's keyid is authorized.
            # Subkeys of authorized main keys are authorized implicitly.
            for authorized_keyid in step.pubkeys:
                authorized_key = layout.keys.get(authorized_keyid)
                main_key_for_subkey = main_keys_for_subkeys.get(
                    authorized_keyid
                )

                # The signing key is authorized ...
                if authorized_key and link_keyid == authorized_keyid:
                    verification_key = authorized_key
                    break

                # ... or the signing key is an authorized subkey ...
                if main_key_for_subkey and link_keyid == authorized_keyid:
                    verification_key = main_key_for_subkey
                    break

                # ... or the signing key is a subkey of an authorized key
                if authorized_key and link_keyid in authorized_key.get(
                    "subkeys", {}
                ):
                    verification_key = authorized_key
                    break

            else:
                LOG.info(
                    "Skipping link. Keyid '%s' is not authorized to sign links"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            # Verify signature and skip invalidly signed links
            try:
                link.verify_signature(verification_key)

            except SignatureVerificationError:
                LOG.info(
                    "Skipping link. Broken link signature with keyid '%s'"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            except KeyExpirationError as e:
                LOG.info("Skipping link. %s", e)
                continue

            # Warn if there are links signed by different subkeys of same main key
            if verification_key["keyid"] in used_main_keyids:
                LOG.warning(
                    "Found links signed by different subkeys of the same main"
                    " key '%s' for step '%s'. Only one of them is counted towards the"
                    " step threshold.",
                    verification_key["keyid"],
                    step.name,
                )

            used_main_keyids.append(verification_key["keyid"])

            # Keep only links with valid and authorized signature
            verified_key_link_dict[link_keyid] = link

        # For each step, verify that we have enough validly signed links from
        # distinct authorized functionaries. Links signed by different subkeys of
        # the same main key are counted only once towards the threshold.
        valid_authorized_links_cnt = len(set(used_main_keyids))
        distinct_signers = sorted(set(used_main_keyids))
        # TODO: To guarantee that links are signed by different functionaries
        # we rely on the layout to not carry duplicate verification keys under
        # different dictionary keys, e.g. {keyid1: KEY1, keyid2: KEY1}
        # Maybe we should add such a check to the layout validation? Or here?

        if report is not None:
            _record_signer_counts(
                report,
                step,
                step_metadata,
                valid_authorized_links_cnt,
                distinct_signers,
            )

        if valid_authorized_links_cnt < step.threshold:
            message = (
                f"Step '{step.name}' requires at least '{step.threshold}' links"
                " validly signed by different authorized functionaries. Only"
                f" found '{valid_authorized_links_cnt}'"
            )
            if report is None:
                raise ThresholdVerificationError(message)

            # Zero metadata for the step is reported as "undetermined" during
            # loading (there is nothing to count). Here, at least one piece of
            # metadata exists, so the signer deficit is a definite failure.
            if len(step_metadata) > 0:
                _add_item_issue(
                    report,
                    step.name,
                    make_issue(
                        CATEGORY_INSUFFICIENT_SIGNERS,
                        message
                        + f", missing '{step.threshold - valid_authorized_links_cnt}'"
                        " distinct signer(s)."
                        f" Satisfied signers: '{valid_authorized_links_cnt}',"
                        f" missing signers:"
                        f" '{step.threshold - valid_authorized_links_cnt}',"
                        f" required signers: '{step.threshold}'.",
                        path=step_paths.get(step.name, (step.name,)),
                        details={
                            "satisfied_signers": valid_authorized_links_cnt,
                            "missing_signers": step.threshold
                            - valid_authorized_links_cnt,
                            "required_signers": step.threshold,
                            "found_metadata": len(step_metadata),
                            "signer_keyids": distinct_signers,
                        },
                    ),
                )

        # Add all good links of this step to the dictionary of links of all steps
        verified_steps_metadata[step.name] = verified_key_link_dict

    # Threshold verification succeeded, return valid and authorized links for
    # further verification
    return verified_steps_metadata


def _record_signer_counts(
    report, step, step_metadata, satisfied, signer_keyids
):
    """Attach threshold and signer counts to a step's report item."""
    item = _find_item(report, step.name)
    if item is None:
        return
    item.threshold = step.threshold
    item.satisfied_signers = satisfied
    item.missing_signers = max(step.threshold - satisfied, 0)
    item.signer_keyids = tuple(signer_keyids)
    item.found_metadata = len(step_metadata)


def verify_command_alignment(command, expected_command):
    """
    <Purpose>
      Checks if a run command aligns with an expected command. The commands align
      if all of their elements are equal. If alignment fails, a warning is
      printed.

      Note:
        Command alignment is a weak guarantee. Because a functionary can easily
        alias commands.

    <Arguments>
      command:
              A command list, e.g. ["vi", "foo.py"]
      expected_command:
              A command list, e.g. ["make", "install"]

    <Exceptions>
      None.

    <Side Effects>
      Logs warning in case commands do not align.

    """
    # In what case command alignment should fail and how that failure should be
    # propagated has been thoughly discussed in:
    # https://github.com/in-toto/in-toto/issues/46 and
    # https://github.com/in-toto/in-toto/pull/47
    # We chose the simplest solution for now, i.e. Warn if they do not align.
    if command != expected_command:
        LOG.warning(
            "Run command '%s' differs from expected command '%s'",
            command,
            expected_command,
        )


def verify_all_steps_command_alignment(layout, chain_link_dict):
    """
    <Purpose>
      Iteratively checks if all expected commands as defined in the
      Steps of a Layout align with the actual commands as recorded in the Link
      metadata.

    <Arguments>
      layout:
              A Layout object to extract the expected commands from.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for step in layout.steps:
        # Find the according link for this step
        expected_command = step.expected_command
        key_link_dict = chain_link_dict[step.name]

        # FIXME: I think we could do this for one link per step only
        # providing that we verify command alignment AFTER threshold equality
        for keyid, link in key_link_dict.items():
            LOG.info(
                "Verifying command alignment for '%s'...",
                in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                ),
            )

            command = link.command
            verify_command_alignment(command, expected_command)


def verify_match_rule(rule_data, artifacts_queue, source_artifacts, links):
    """
    <Purpose>
      Filters artifacts from artifact queue using rule pattern and optional rule
      source prefix and consumes them if there is a corresponding destination
      artifact, filtered using the same rule pattern and an optional rule
      destination prefix, and source and destination artifacts have matching
      hashes.

      NOTE: The destination artifacts are extracted from the links dictionary,
      using destination name and destination type from the rule data. The source
      artifacts could also be extracted from the links dictionary, but would
      require the caller to pass source name and source type, as those are not
      encoded in the rule. However, we choose to let the caller directly pass the
      relevant artifacts.


    <Arguments>
      rule_data:
              An unpacked "MATCH" rule (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).


      source_artifacts:
              All artifacts of the source item (including hashes).

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    consumed = set()

    # The rule can only consume artifacts if the destination link exists
    dest_link = links.get(rule_data["dest_name"])
    if not dest_link:
        return consumed

    # Extract destination artifacts from destination link
    dest_artifacts = getattr(dest_link, rule_data["dest_type"])

    # Filter part 1 - Filter artifacts using optional source prefix, and subtract
    # prefix before filtering with rule pattern (see filter part 2) to prevent
    # globbing in the prefix.
    if rule_data["source_prefix"]:
        # Add trailing slash to source prefix if it does not exist
        normalized_source_prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")

        filtered_source_paths = [
            artifact_path[len(normalized_source_prefix) :]
            for artifact_path in artifacts_queue
            if artifact_path.startswith(normalized_source_prefix)
        ]

    else:
        filtered_source_paths = artifacts_queue

    # Filter part 2 - glob above filtered artifact paths
    filtered_source_paths = fnmatch.filter(
        filtered_source_paths, rule_data["pattern"]
    )

    # Iterate over filtered source paths and try to match the corresponding
    # source artifact hash with the corresponding destination artifact hash
    for path in filtered_source_paths:
        # If a source prefix was specified, we subtracted the prefix above before
        # globbing. We have to re-prepend the prefix in order to retrieve the
        # corresponding source artifact below.
        if rule_data["source_prefix"]:
            full_source_path = os.path.join(
                rule_data["source_prefix"], path
            ).replace("\\", "/")

        else:
            full_source_path = path

        # If a destination prefix was specified, the destination artifact should
        # be queried with the full destination path, i.e. the prefix joined with
        # the globbed path.
        if rule_data["dest_prefix"]:
            full_dest_path = os.path.join(
                rule_data["dest_prefix"], path
            ).replace("\\", "/")

        else:
            full_dest_path = path

        # Extract source artifact hash dict
        # We know the source artifact is available, it is also in the queue
        source_artifact = source_artifacts[full_source_path]

        # Don't consume source artifact w/o corresponding dest artifact (by path)
        try:
            dest_artifact = dest_artifacts[full_dest_path]
        except KeyError:
            continue

        # Don't consume source artifact w/o corresponding dest artifact (by hash)
        if source_artifact != dest_artifact:
            continue

        # Source and destination matched, consume artifact
        consumed.add(full_source_path)

    return consumed


def verify_create_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are not in the materials set but are in the products set, i.e.
      were created.

    <Arguments>
      rule_pattern:
              A "CREATE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are products but not materials
    return set(filtered_artifacts) & (products - materials)


def verify_delete_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in the materials set but are not in the products set, i.e.
      were deleted.

    <Arguments>
      rule_pattern:
              A "DELETE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are materials but not products
    return set(filtered_artifacts) & (materials - products)


def verify_modify_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in both the materials dict and in the products doct, but have
      different hashes, i.e. were modified.

    <Arguments>
      rule_pattern:
              A "MODIFY" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (including hashes).

      products:
              All products of an item (including hashes).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Filter filtered artifacts that are materials and products
    filtered_artifacts = (
        set(filtered_artifacts) & set(materials.keys()) & set(products.keys())
    )

    # Consume filtered artifacts that have different hashes
    consumed = set()
    for path in filtered_artifacts:
        if materials[path] != products[path]:
            consumed.add(path)

    return consumed


def verify_allow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Consumes artifacts, filtered from the artifacts queue using rule pattern.

    <Arguments>
      rule_pattern:
              An "ALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume all filtered artifacts
    return set(filtered_artifacts)


def verify_disallow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if rule pattern applies to any artifacts in
      the queue.

      NOTE: Each set of rules should have a terminal DISALLOW rule to make
      overall verification fail in case preceding rules did not consume all
      artifacts as intended.

    <Arguments>
      rule_pattern:
              A "DISALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError
          if the rule pattern filters artifacts in the artifact queue.

    <Side Effects>
      None.

    <Returns>
      None.

    """
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    if filtered_artifacts:
        raise RuleVerificationError(
            f"'DISALLOW {rule_pattern}' matched the following artifacts: {filtered_artifacts}\n{_get_artifact_rule_traceback()}"
        )


def verify_require_rule(filename, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if the filename provided does not exist in the
      artifacts_queue

    <Arguments>
      filename:
              A single filename (see issues #193 and #152). We will ignore the
              artifact rule pattern because it's ambiguous and instead treat it
              as a literal file name.

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError:
        if the filename is not present in the artifacts queue

    <Side Effects>
      None.

    <Returns>
      None.

    """
    if filename not in artifacts_queue:
        raise RuleVerificationError(
            f"'REQUIRE {filename}' did not find {filename} "
            f"in: {artifacts_queue}\n{_get_artifact_rule_traceback()}"
        )


def _get_artifact_rule_traceback():
    """Build and return string form global `RULE_TRACE` which may be used as
    error message for RuleVerificationError.

    """
    traceback_str = "Full trace for 'expected_{}' of item '{}':\n".format(
        RULE_TRACE["source_type"], RULE_TRACE["source_name"]
    )

    # Show all materials and products available in the beginning and
    # label the one that is used to generate a queue.
    for source_type in ["materials", "products"]:
        traceback_str += "Available {}{}:\n{}\n".format(
            source_type,
            [" (used for queue)", ""][RULE_TRACE["source_type"] != source_type],
            RULE_TRACE[source_type],
        )

    for trace_entry in RULE_TRACE["trace"]:
        traceback_str += "Queue after '{}':\n".format(
            " ".join(trace_entry["rule"])
        )
        traceback_str += "{}\n".format(trace_entry["queue"])

    return traceback_str


def verify_item_rules(  # noqa: C901, PLR0912, PLR0913, PLR0915, PLR0917
    source_name, source_type, rules, links, issue_sink=None, path=None
):
    """
    <Purpose>
      Apply all passed material or product rules (see source_type) of a given
      step or inspection (see source_name), to enforce and authorize the
      corresponding artifacts and to guarantee that artifacts are linked together
      across steps of the supply chain.

      The mode of operation is similar to that of a firewall:
      In the beginning all materials or products of the step or inspection are
      placed into an artifact queue. The rules are then applied sequentially,
      consuming artifacts in the queue, i.e. removing them from the queue upon
      successful application.

      The consumption of artifacts by itself has no effects on the verification.
      Only through a subsequent "DISALLOW" rule, that finds unconsumed artifacts,
      is an exception raised. Similarly does the "REQUIRE" rule raise exception,
      if it does not find the artifact it requires, because it has falsely been
      consumed or was not there from the beginning.



    <Arguments>
      source_name:
              The name of the item (step or inspection) being verified.

      source_type:
              One of "materials" or "products" depending on whether the rules are
              taken from the "expected_materials" or "expected_products" field of
              the item being verified.

      rules:
              The list of rules (material or product rules) for the item being
              verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

      issue_sink: (optional)
              A callable receiving a ``VerificationIssue`` for every failed
              rule. If passed, rule violations and evaluation errors are
              recorded and verification continues with the remaining rules,
              so that all violations of an item are reported at once. Only the
              first violation is used to build the raised exception, if any.

      path: (optional)
              Full report path of the item being verified.

    <Exceptions>
      FormatError
          if source_type is not "materials" or "products", or
          if a rule in the passed list of rules does not conform with any rule
          format.

      RuleVerificationError
          if a DISALLOW rule matches disallowed artifacts, or
          if a REQUIRE rule does not find a required artifact. Not raised if
          an `issue_sink` is passed; the caller is responsible for turning the
          recorded issues into an exception.

    <Side Effects>
      Clears and populates the global RULE_TRACE data structure.

    """
    if source_type not in {"materials", "products"}:
        raise securesystemslib.exceptions.FormatError(
            "Argument 'source_type' of function 'verify_item_rules' has to be "
            f"one of 'materials' or 'products'. Got: '{source_type}'"
        )

    path = tuple(path) if path else (source_name,)

    # Create shortcuts to item's materials and products (including hashes),
    # required to verify "modify" and "match" rules.
    materials_dict = links[source_name].materials
    products_dict = links[source_name].products

    # All other rules only require materials or products paths (without hashes)
    materials_paths = set(materials_dict.keys())
    products_paths = set(products_dict.keys())

    # Depending on the source type we create the artifact queue from the item's
    # materials or products and use it to keep track of (not) consumed artifacts.
    # The queue also only contains artifact keys (without hashes)
    artifacts = getattr(links[source_name], source_type)
    artifacts_queue = set(artifacts.keys())

    # Reset and re-populate rule traceback info dict for a rich error message.
    # In report mode the traceback ends up in the report, which must be
    # deterministic, so its collections are sorted. The legacy exception path
    # keeps the historical insertion order.
    as_list = sorted if issue_sink is not None else list
    RULE_TRACE.clear()
    RULE_TRACE["source_name"] = source_name
    RULE_TRACE["source_type"] = source_type
    RULE_TRACE["materials"] = as_list(materials_dict)
    RULE_TRACE["products"] = as_list(products_dict)
    RULE_TRACE["trace"] = []

    first_exception = None

    # Process rules and remove consumed items from queue in each iteration
    for rule in rules:
        LOG.info("Verifying '%s'...", " ".join(rule))

        # Parse the rule and create two shortcuts to contained rule data
        rule_data = in_toto.rulelib.unpack_rule(rule)
        _type = rule_data["rule_type"]
        pattern = rule_data["pattern"]

        # Initialize empty consumed set as fallback for rules that do not consume
        # artifacts. All rules except "disallow" and "require" consume artifacts.
        consumed = set()

        try:
            if _type == "match":
                consumed = verify_match_rule(
                    rule_data, artifacts_queue, artifacts, links
                )

            elif _type == "create":
                consumed = verify_create_rule(
                    pattern, artifacts_queue, materials_paths, products_paths
                )

            elif _type == "delete":
                consumed = verify_delete_rule(
                    pattern, artifacts_queue, materials_paths, products_paths
                )

            elif _type == "modify":
                consumed = verify_modify_rule(
                    pattern, artifacts_queue, materials_dict, products_dict
                )

            elif _type == "allow":
                consumed = verify_allow_rule(pattern, artifacts_queue)

            # It's up to the "disallow" and "require" rule to raise an error if
            # artifacts were not consumed as intended
            elif _type == "disallow":
                verify_disallow_rule(pattern, artifacts_queue)

            elif _type == "require":
                verify_require_rule(pattern, artifacts_queue)

            else:  # pragma: no cover (unreachable)
                raise securesystemslib.exceptions.FormatError(
                    f"Invaldid rule type '{_type}'."
                )

        except (
            RuleVerificationError,
            securesystemslib.exceptions.FormatError,
        ) as exc:
            if issue_sink is None:
                raise

            # Report the violation and continue, so that every rule of every
            # item gets an independent outcome. A failed rule consumed
            # nothing, so the queue stays unchanged for the remaining rules.
            if first_exception is None:
                first_exception = exc
            issue_sink(
                _rule_issue(
                    exc, rule, rule_data, source_type, artifacts_queue, path
                )
            )

        else:
            artifacts_queue -= consumed

        # Append rule and copy of queue to global info for a rich error message
        RULE_TRACE["trace"].append(
            {"rule": rule, "queue": as_list(artifacts_queue)}
        )

    if issue_sink is not None and first_exception is not None:
        # Preserve the first rule failure for the legacy exception path, while
        # the report keeps every failure for the caller.
        raise first_exception


def _rule_issue(  # noqa: PLR0913, PLR0917
    exc, rule, rule_data, source_type, artifacts_queue, path
):
    """Build a structured issue from a rule verification failure."""
    rule_type = rule_data["rule_type"]
    details = {
        "rule": list(rule),
        "source_type": source_type,
        "rule_type": rule_type,
        "error": exception_chain(exc),
    }

    if rule_type == "disallow":
        # Name the artifacts that the rule rejected.
        details["artifacts"] = sorted(
            fnmatch.filter(artifacts_queue, rule_data["pattern"])
        )

    elif rule_type == "require":
        details["artifacts"] = [rule_data["pattern"]]

    return make_issue(
        CATEGORY_RULE_VIOLATION,
        str(exc),
        path=path,
        details=details,
    )


def verify_all_item_rules(items, links, report=None, paths=None):
    """
    <Purpose>
      Iteratively verifies artifact rules of passed items (Steps or Inspections).

    <Arguments>
      items:
              A list containing Step or Inspection objects whose material
              and product rules will be verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

      report: (optional)
              An ItemResult whose nested item results receive the findings. If
              passed, rule violations do not abort the item or the batch; they
              are recorded per verified item, so that later items still get an
              independent result. The first violation is re-raised afterwards
              to preserve legacy behaviour.

      paths: (optional)
              A mapping of item name to full report path.

    <Exceptions>
      RuleVerificationError and FormatError, as produced by
      ``verify_item_rules``, if `report` is None (historical behaviour).

    <Side Effects>
      None.

    """
    paths = paths or {}
    first_exception = None

    for item in items:
        item_result = None
        if report is not None:
            kind = (
                "inspection"
                if item.__class__.__name__ == "Inspection"
                else "step"
            )
            item_result = _find_item(report, item.name)
            if item_result is None:
                item_result = report.get_or_add_child(item.name, kind=kind)

        issue_sink = item_result.add_issue if item_result is not None else None
        path = paths.get(item.name, (item.name,))

        LOG.info("Verifying material rules for '%s'...", item.name)
        try:
            verify_item_rules(
                item.name,
                "materials",
                item.expected_materials,
                links,
                issue_sink=issue_sink,
                path=path,
            )
        except (
            RuleVerificationError,
            securesystemslib.exceptions.FormatError,
        ) as exc:
            if first_exception is None:
                first_exception = exc

        LOG.info("Verifying product rules for '%s'...", item.name)
        try:
            verify_item_rules(
                item.name,
                "products",
                item.expected_products,
                links,
                issue_sink=issue_sink,
                path=path,
            )
        except (
            RuleVerificationError,
            securesystemslib.exceptions.FormatError,
        ) as exc:
            if first_exception is None:
                first_exception = exc

    if first_exception is not None and report is None:
        # Historical fail-fast behaviour; report-driven callers rely on the
        # recorded issues instead.
        raise first_exception


def verify_threshold_constraints(
    layout, chain_link_dict, report=None, step_paths=None
):
    """
    <Purpose>
      Verifies that all links corresponding to a given step report the same
      materials and products.

      NOTE: This function does not verify if the signatures of each link
      corresponding to a step are valid or created by a different authorized
      functionary. This should be done earlier, using the function
      `verify_link_signature_thresholds`.

      NOTE: Links signed by a master key and by one of its subkeys belong to
      the same functionary. They are compared like any other pair of links,
      i.e. contradictory artifact lists are reported for the same signer too.

    <Arguments>
      layout:
              The layout whose step thresholds are being verified

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

      report: (optional)
              A VerificationReport (or ItemResult for a sublayout). If passed,
              inconsistencies are recorded per step, naming the conflicting
              artifact entries, instead of raising on the first conflict.

      step_paths: (optional)
              A mapping of step name to full report path.

    <Exceptions>
      ThresholdVerificationError
          If there are not enough (threshold) links for a steps

          If the artifacts for all links of a step are not equal

          Only raised if no `report` is passed.

    <Side Effects>
      None.

    """

    step_paths = step_paths or {}

    # We are only interested in links that are related to steps defined in the
    # Layout, so iterate over layout.steps
    for step in layout.steps:
        # Skip steps that don't require multiple functionaries
        if step.threshold <= 1:
            LOG.info(
                "Skipping threshold verification for step '%s' with"
                " threshold '%s'...",
                step.name,
                step.threshold,
            )
            continue

        LOG.info(
            "Verifying threshold for step '%s' with threshold '%s'...",
            step.name,
            step.threshold,
        )
        # Extract the key_link_dict for this step from the passed chain_link_dict
        key_link_dict = chain_link_dict[step.name]

        # Check if we have at least <threshold> links for this step
        # NOTE: This is already done in `verify_link_signature_thresholds`,
        # Should we remove the check?
        if len(key_link_dict) < step.threshold:
            message = (
                f"Step '{step.name}' not performed by enough functionaries!"
            )
            if report is None:
                raise ThresholdVerificationError(message)
            # Signature threshold verification already reported the concrete
            # signer deficit for this step. Do not duplicate it, and do not
            # claim artifact inconsistency when there is nothing to compare.
            LOG.info(
                "Skipping artifact constraint verification for step '%s'."
                " Not enough links were available.",
                step.name,
            )
            continue

        # Compare all links against a reference link, chosen by sorted keyid
        # so the reported pair of filenames is deterministic.
        reference_keyid = min(key_link_dict)
        reference_link = key_link_dict[reference_keyid]

        # Iterate over all links to compare their properties with a reference_link
        for keyid in sorted(key_link_dict):
            link = key_link_dict[keyid]
            # TODO: Do we only care for artifacts, or do we want to
            # assert equality of other properties as well?
            if (
                reference_link.materials != link.materials
                or reference_link.products != link.products
            ):
                message = (
                    "Links '{}' and '{}' have different artifacts!".format(
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=reference_keyid
                        ),
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=keyid
                        ),
                    )
                )
                if report is None:
                    raise ThresholdVerificationError(message)

                deviations = _artifact_deviations(reference_link, link)
                _add_item_issue(
                    report,
                    step.name,
                    make_issue(
                        CATEGORY_INCONSISTENT_ARTIFACTS,
                        message + " Conflicting entries:"
                        f" {', '.join(_describe_deviations(deviations))}.",
                        path=step_paths.get(step.name, (step.name,)),
                        details={
                            "materials": deviations["materials"],
                            "products": deviations["products"],
                            "reference_keyid": reference_keyid,
                            "conflicting_keyid": keyid,
                        },
                    ),
                )


def _artifact_deviations(reference_link, link):
    """Return artifact paths whose presence or hashes differ between links.

    The result has the form::

        {
          "materials": {
            "<path>": {"reference": <hashdict|None>, "conflicting": <hashdict|None>},
            ...
          },
          "products": {...},
        }

    Entries are determined by path, so an artifact present on only one side is
    reported with ``None`` on the other side.
    """
    deviations = {"materials": {}, "products": {}}
    for artifact_type in ("materials", "products"):
        reference_artifacts = getattr(reference_link, artifact_type)
        conflicting_artifacts = getattr(link, artifact_type)
        for path in sorted(
            set(reference_artifacts) | set(conflicting_artifacts)
        ):
            reference_hash = reference_artifacts.get(path)
            conflicting_hash = conflicting_artifacts.get(path)
            if reference_hash != conflicting_hash:
                deviations[artifact_type][path] = {
                    "reference": reference_hash,
                    "conflicting": conflicting_hash,
                }
    return deviations


def _describe_deviations(deviations):
    """Return a deterministic list of human readable deviation strings."""
    descriptions = []
    for artifact_type in ("materials", "products"):
        for path, hashes in deviations[artifact_type].items():
            if hashes["reference"] is None:
                kind = "only in conflicting link"
            elif hashes["conflicting"] is None:
                kind = "only in reference link"
            else:
                kind = "hash mismatch"
            descriptions.append(f"{artifact_type}:{path} ({kind})")
    return descriptions


def reduce_chain_links(chain_link_dict):
    """
    <Purpose>
      Iterates through the passed chain_link_dict and builds a dict with
      step-name as keys and link objects as values.
      We already check if the links of different functionaries are
      identical.

    <Arguments>
      layout:
              The layout specified by the project owner against which the
              threshold will be verified.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing one Link metadata object per step only if
      the link artifacts of all link objects are identical for a step.

    """

    reduced_chain_link_dict = {}

    for step_name in sorted(chain_link_dict):
        key_link_dict = chain_link_dict[step_name]
        # Extract the key_link_dict for this step from the passed chain_link_dict
        # take one exemplary link, chosen by sorted keyid so the choice does not
        # depend on dictionary insertion or hash order
        # form the reduced_chain_link_dict to return
        reduced_chain_link_dict[step_name] = key_link_dict[min(key_link_dict)]

    return reduced_chain_link_dict


def verify_sublayouts(  # noqa: C901, PLR0913, PLR0917
    layout,
    steps_metadata,
    superlayout_link_dir_path,
    inspect_timeout,
    report=None,
    step_paths=None,
    step_order=None,
    verify_sublayout=None,
):
    """
    <Purpose>
      Extracts link or layout object for each step in steps_metadata. Checks if
      any step has been delegated by the functionary, recurses into the
      delegation, and replaces the layout object with an equivalent link object.
      Returns the extracted link objects in a dict called chain_link_dict.

    <Arguments>
      layout:
              The layout specified by the project owner.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                            object>,
                  ...
                }, ...
              }

      superlayout_link_dir_path:
              A path to a directory, where links of the superlayout are loaded
              from. Links of the sublayout are expected to be in a subdirectory
              relative to this path, with a name in the format
              in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.

      inspect_timeout:
              Integer value that is the number of seconds to pass to the run
              command to timeout the subprocess within.

      report: (optional)
              An ItemResult whose nested item results receive sublayout
              findings. Nested failures carry the complete outer step path.

      step_paths: (optional)
              A mapping of step name to full report path.

      step_order: (optional)
              Step names in dependency order. Sublayouts are verified in this
              order, so the order never depends on dictionary order.

      verify_sublayout: (optional)
              Callable ``(metadata, layout_key_dict, step_name, link_dir_path,
              step_path, report_item) -> Link`` used for the recursive
              verification. Defaults to ``in_toto_verify`` without a report,
              i.e. the historical behaviour.

    <Exceptions>
      raises an Exception if verification of the delegated step fails. If a
      `report` is passed, sublayout failures are recorded instead and the
      remaining steps are still verified.

    <Returns>
      The passed dictionary containing Link objects instead of metadata per
      functionary per step, with layouts replaced with summary links.
      e.g.:
      {
        <link name> : {
          <functionary key id> : <Link object>,
          ...
        }, ...
      }

    """
    chain_link_dict = {}
    step_paths = step_paths or {}

    for step_name in step_order or sorted(steps_metadata):
        metadata_dict = steps_metadata[step_name]
        # Steps whose metadata was loaded are always reported, even when there
        # is none, so a step can never silently disappear from a report.
        if report is not None:
            _sublayout_parent_item(
                report,
                step_name,
                step_paths.get(step_name, (step_name,)),
            )
        key_link_dict = {}
        for keyid in sorted(metadata_dict):
            metadata = metadata_dict[keyid]
            try:
                payload = metadata.get_payload()
            except Exception:  # noqa: BLE001
                # Malformed metadata was recorded during loading.
                LOG.info(
                    "Skipping unparseable metadata for step '%s' (keyid '%s').",
                    step_name,
                    keyid,
                )
                continue

            if payload.type_ == "layout":
                LOG.info("Verifying sublayout %s...", step_name)
                layout_key_dict = {}

                # Retrieve the entire key object for the keyid
                # corresponding to the link
                layout_key_dict = {keyid: layout.keys.get(keyid)}

                # Sublayout links are expected to be in a directory with the following
                # name relative the the current link directory path, i.e. if there
                # are multiple levels of sublayout nesting, the links are expected to
                # be nested accordingly
                sub_link_dir = (
                    in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
                        name=step_name, keyid=keyid
                    )
                )

                sublayout_link_dir_path = os.path.join(
                    superlayout_link_dir_path, sub_link_dir
                )

                path = step_paths.get(step_name, (step_name,))

                try:
                    if verify_sublayout is None:
                        summary_link = in_toto_verify(
                            metadata,
                            layout_key_dict,
                            link_dir_path=sublayout_link_dir_path,
                            step_name=step_name,
                            inspect_timeout=inspect_timeout,
                        )
                    else:
                        summary_link = verify_sublayout(
                            metadata,
                            layout_key_dict,
                            step_name,
                            sublayout_link_dir_path,
                            path,
                            report,
                        )
                except LayoutReferenceError:
                    # Malformed references in a delegated layout are layout
                    # errors, not verification findings: they abort verification
                    # the same way they do for the root layout.
                    raise
                except Exception as exc:
                    if report is None:
                        raise
                    # Record the failure with the outer step path and continue
                    # with the remaining delegates of this step.
                    nested = _sublayout_parent_item(report, step_name, path)
                    if not any(
                        issue.category == CATEGORY_SUBLAYOUT_FAILURE
                        for issue in nested.issues
                    ):
                        nested.add_issue(
                            make_issue(
                                CATEGORY_SUBLAYOUT_FAILURE,
                                f"Sublayout verification for step"
                                f" '{step_name}' failed: {exc}",
                                path=path,
                                details={"error": exception_chain(exc)},
                            )
                        )
                    payload = in_toto.models.link.Link(name=step_name)
                    key_link_dict[keyid] = payload
                    continue

                # Replace the layout object with the link object returned
                # by in-toto-verify
                payload = summary_link

            key_link_dict[keyid] = payload
        chain_link_dict[step_name] = key_link_dict

    return chain_link_dict


def _sublayout_parent_item(report, step_name, path, kind="step"):
    """Return (and create if needed) the report item for a delegated step."""
    if isinstance(report, VerificationReport):
        item = _find_item(report, step_name)
        if item is None:
            item = ItemResult(name=step_name, path=path, kind=kind)
            report.steps.append(item)
        return item

    if isinstance(report, ItemResult):
        item = _find_item(report, step_name)
        if item is None:
            item = ItemResult(name=step_name, path=path)
            report.sub_reports.append(item)
        return item

    return None  # pragma: no cover (caller guarantees a report)


def merge_sublayout_report(parent_item, nested_report):
    """Attach a nested layout report to its delegating step item.

    Nested step results are kept as sub-reports, so their failures remain
    attributable to inner steps while also carrying the full outer path.
    Layout-level findings of the nested layout (e.g. a bad signature on the
    delegated layout) are attached to the delegating step.
    """
    parent_item.sub_reports.extend(nested_report.steps)
    parent_item.sub_reports.extend(nested_report.inspections)
    for issue in nested_report.issues:
        # Layout-level findings of the nested layout (e.g. a bad signature on
        # the delegated layout, or an expired sublayout) belong to the step
        # that delegated. They already carry the full path from the root.
        parent_item.add_issue(issue)

    # The parent's final status is derived by ItemResult.finalize from our
    # issues and nested reports, so no status is pinned here on purpose.
    return parent_item


def get_summary_link(layout, reduced_chain_link_dict, name):
    """
    <Purpose>
      Merges the materials of the first step (as mentioned in the layout)
      and the products of the last step and returns a new link.
      This link reports the materials and products and summarizes the
      overall software supply chain.
      NOTE: The assumption is that the steps mentioned in the layout are
      to be performed sequentially. So, the first step mentioned in the
      layout denotes what comes into the supply chain and the last step
      denotes what goes out.

    <Arguments>
      layout:
              The layout specified by the project owner.

      reduced_chain_link_dict:
              A dictionary containing link metadata per step,
              e.g.:
              {
                <link name> : <Link object>,
                ...
              }
      name:
              The name that the summary link will be associated with.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A Link object which summarizes the materials and products of the overall
      software supply chain.

    """
    # Create empty link object
    summary_link = in_toto.models.link.Link()

    # Take first and last link in the order the corresponding
    # steps appear in the layout, if there are any.
    if len(layout.steps) > 0:
        first_step_link = reduced_chain_link_dict[layout.steps[0].name]
        last_step_link = reduced_chain_link_dict[layout.steps[-1].name]

        summary_link.materials = first_step_link.materials
        summary_link.name = name

        summary_link.products = last_step_link.products
        summary_link.byproducts = last_step_link.byproducts
        summary_link.command = last_step_link.command

    return summary_link


def in_toto_verify(  # noqa: PLR0913, PLR0917, RUF100
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
    step_name="",
    persist_inspection_links=True,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
    report=None,
    _step_path=(),
):
    """Performs complete in-toto supply chain verification for a final product.

    The verification procedure consists of the following activities, performed in
    the given order:

    1.  Verify layout signatures
    2.  Validate step references and derive dependency order
    3.  Verify layout expiration date
    4.  Substitute placeholders in the layout
    5.  Load link metadata
    6.  Verify link signatures with keys in layout
    7.  Recurse into sublayout verification
    8.  Soft-verify alignment of reported and expected commands. Note:
        verification does not fail if commands don't match, instead a warning is
        logged as per the in-toto specification --
        https://github.com/in-toto/docs/blob/master/in-toto-spec.md#431-steps
    9.  Verify threshold artifact constraints
    10. Process step product and material rules
    11. Execute inspection commands and generate inspection links
    12. Process inspection product and material rules

    Without a ``report`` argument, verification stops at the first failed check
    and raises, exactly like before. With a ``report`` argument, every step and
    inspection is verified independently, all failures are attributed to the
    item and check that produced them, and the report is filled in even if
    verification fails. In that mode this function returns the summary link and
    stores it on the report (`report.summary_link`), rather than raising for
    ordinary verification failures.

    Note: in-toto's verification workflow directly uses the key for verifying
    signatures. It does not communicate with external sources of information for
    specific attributes about keys. This ensures that verification can be
    performed in isolation. It is the supply chain owner's responsibility to
    consider such attributes before using the key to sign the layout or adding
    it to the layout. For example, in-toto does not rely on the creation time,
    revocation status, and usage flags for PGP keys. To revoke or otherwise
    affect the usage of a key, the supply chain owner must sign a new layout
    with the corresponding changes.

    Arguments:
      metadata: A Metadata object that contains a Layout object to be verified.

      layout_key_dict: A public key dictionary. The verification routine requires
          at least one key, and a valid signature on the layout for each key.

      link_dir_path (optional): A directory path to link metadata files. The
          expected filename format for link metadata files is
          ``STEP-NAME.KEYID-PREFIX.link``. Link metadata files for a sublayout
          are loaded from a subdirectory relative to the link_dir_path of the
          superlayout. The expected directory name format is
          ``SUBLAYOUT-STEP-NAME.KEYID-PREFIX``.

      substitution_parameters (optional): A dictionary with substitution values
          for artifact rules (steps and inspections), the expected command
          attribute (steps), and the run attribute (inspections) in the layout.

      step_name (optional): A name assigned to the returned link. This is mostly
          useful during recursive sublayout verification.

      persist_inspection_links (optional): A boolean that determines whether or
          not link metadata files for inspection are written to cwd.

      inspect_timeout (optional): An integer value that defaults to
          in_toto.settings.LINK_CMD_EXEC_TIMEOUT in seconds which ends up timing
          out the run command subprocess if it runs over.

      report (optional): A ``VerificationReport`` to fill in. If passed, the
          return type is unchanged (the summary link), but the report receives
          per-item results, signer counts and attributed issues, and ordinary
          verification failures are no longer raised. Pass
          ``report.summary_link`` to retrieve the summary link.

      _step_path (internal): Full report path prefix used during recursion into
          sublayouts. Not part of the public API.

    Raises:
      securesystemslib.exceptions.FormatError: Passed parameters are malformed.

      LayoutReferenceError: A rule references a nonexistent step, or step
          references form a cycle. Raised before any verification work starts.

      SignatureVerificationError: No layout verification key is passed, or any of
          the passed keys fails to verify a signature.

      LayoutExpiredError: The layout is expired.

      LinkNotFoundError: Fewer than threshold link metadata files can be found
          for a step of the layout.

      ThresholdVerificationError: Fewer than threshold links, validly signed by
          different authorized functionaries, who agree on the recorded materials
          and products, can be found for a step of the layout. (Links with
          invalid signatures or signatures by unauthorized functionaries are
          ignored.)

      RuleVerificationError: A DISALLOW rule matches disallowed artifacts, or
          a REQUIRE rule does not find a required artifact.

      BadReturnValueError: An inspection command returns a non-zero value.

    Side Effects:
      Reads link metadata files from disk.
      Runs inspection commands in subprocess.

    Returns:
      A Link object, which summarizes the materials and products of the overall
      software supply chain. This is mostly useful during recursive sublayout
      verification.

    """
    if report is not None:
        return _in_toto_verify_reporting(
            metadata,
            layout_key_dict,
            link_dir_path,
            substitution_parameters,
            step_name,
            persist_inspection_links,
            inspect_timeout,
            report,
            _step_path,
        )

    LOG.info("Verifying layout metadata signatures...")
    verify_metadata_signatures(metadata, layout_key_dict)

    # For the rest of the verification we only care about the layout payload
    # (Layout) that carries all the information and not about the layout
    # container (Metablock) that also carries the signatures
    LOG.info("Extracting layout from metadata...")
    layout = metadata.get_payload()

    LOG.info("Validating step references...")
    verify_step_order(layout)

    LOG.info("Verifying layout expiration...")
    verify_layout_expiration(layout)

    # If there are parameters sent to the translation layer, substitute them
    if substitution_parameters is not None:
        LOG.info("Performing parameter substitution...")
        substitute_parameters(layout, substitution_parameters)

    LOG.info("Reading link metadata files...")
    steps_metadata = load_links_for_layout(layout, link_dir_path)

    LOG.info("Verifying link metadata signatures...")
    steps_metadata = verify_link_signature_thresholds(layout, steps_metadata)

    LOG.info("Verifying sublayouts...")
    chain_link_dict = verify_sublayouts(
        layout, steps_metadata, link_dir_path, inspect_timeout
    )

    LOG.info("Verifying alignment of reported commands...")
    verify_all_steps_command_alignment(layout, chain_link_dict)

    LOG.info("Verifying threshold constraints...")
    verify_threshold_constraints(layout, chain_link_dict)
    reduced_chain_link_dict = reduce_chain_links(chain_link_dict)

    # NOTE: Processing step rules before executing inspections guarantees that
    # inspection commands don't run on compromised target files, however, this
    # also precludes step match rules from referencing inspection artifacts.
    LOG.info("Verifying Step rules...")
    verify_all_item_rules(layout.steps, reduced_chain_link_dict)

    LOG.info("Executing Inspection commands...")
    inspection_link_dict = run_all_inspections(
        layout, persist_inspection_links, inspect_timeout
    )

    LOG.info("Verifying Inspection rules...")
    # Artifact rules for inspections can reference links that correspond to
    # Steps or Inspections, hence the concatenation of both collections of links
    combined_links = reduced_chain_link_dict.copy()
    combined_links.update(inspection_link_dict)
    verify_all_item_rules(layout.inspect, combined_links)

    # We made it this far without exception that means, verification passed
    LOG.info("The software product passed all verification.")

    # Return a link file which summarizes the entire software supply chain
    # This is mostly relevant if the currently verified supply chain is embedded
    # in another supply chain
    return get_summary_link(layout, reduced_chain_link_dict, step_name)


def _in_toto_verify_reporting(  # noqa: C901, PLR0912, PLR0913, PLR0915, PLR0917
    metadata,
    layout_key_dict,
    link_dir_path,
    substitution_parameters,
    step_name,
    persist_inspection_links,
    inspect_timeout,
    report,
    step_path,
):
    """Report-driven verification. See ``in_toto_verify`` for the contract.

    Checks that can be evaluated without metadata (layout signature,
    references, expiration) are layout-level. Every step and inspection
    otherwise gets its own result; a failure in one never prevents the others
    from being checked.
    """
    # 1. Layout-level checks. These are recorded, but verification continues so
    # that the report is as complete as possible. A bad layout signature still
    # makes the overall verdict fail.
    try:
        verify_metadata_signatures(metadata, layout_key_dict)
    except Exception as exc:  # noqa: BLE001
        report.add_issue(
            make_issue(
                CATEGORY_LAYOUT_SIGNATURE,
                f"Layout signature verification failed: {exc}",
                path=step_path,
                details={"error": exception_chain(exc)},
            )
        )

    try:
        layout = metadata.get_payload()
    except Exception as exc:  # noqa: BLE001
        # Without a payload nothing else can be verified.
        report.add_issue(
            make_issue(
                CATEGORY_LAYOUT_SIGNATURE,
                f"Could not extract layout payload: {exc}",
                path=step_path,
                details={"error": exception_chain(exc)},
            )
        )
        report.complete = False
        report.finalize()
        return None

    # 2. Validate references and derive deterministic dependency order before
    # any files are read. Malformed references abort verification by design.
    step_order = _validate_step_references(layout)
    ordered_names = _topological_order(step_order)
    report.ordered_step_names = list(ordered_names)
    step_paths = {
        name: (*step_path, name) for name in layout.get_step_name_list()
    }

    try:
        verify_layout_expiration(layout)
    except Exception as exc:  # noqa: BLE001
        report.add_issue(
            make_issue(
                CATEGORY_LAYOUT_EXPIRED,
                f"Layout expired: {exc}",
                path=step_path,
                details={"error": exception_chain(exc)},
            )
        )

    if substitution_parameters is not None:
        LOG.info("Performing parameter substitution...")
        substitute_parameters(layout, substitution_parameters)

    # Create a result per step up front, in dependency order, so every step
    # gets a conclusion even if loading or verification fails early. When the
    # parent already created a placeholder (it does so before recursing into
    # a delegated layout), reuse it instead of duplicating the step.
    item_by_name = {}
    for name in ordered_names:
        item = _find_item(report, name)
        if item is None:
            item = ItemResult(name=name, path=step_paths[name], kind="step")
            report.steps.append(item)
        item.threshold = layout.get_step_by_name(name).threshold
        item_by_name[name] = item

    # Create inspection results up front too, so they appear in the report even
    # if step verification fails and the commands are never executed.
    inspection_results = {}
    for inspection in layout.inspect:
        item = ItemResult(
            name=inspection.name,
            path=(*step_path, inspection.name),
            kind="inspection",
        )
        report.inspections.append(item)
        inspection_results[inspection.name] = item

    # 3. Load metadata. Unparseable files are skipped and recorded; missing
    # metadata is recorded but does not abort.
    LOG.info("Reading link metadata files...")
    steps_metadata = load_links_for_layout(
        layout,
        link_dir_path,
        report=report,
        step_paths=step_paths,
        raise_on_missing=False,
    )

    # 4. Signature threshold verification, attributed per step.
    LOG.info("Verifying link metadata signatures...")
    steps_metadata = verify_link_signature_thresholds(
        layout, steps_metadata, report=report, step_paths=step_paths
    )

    # 5. Sublayout recursion. Nested results carry the full outer step path.
    LOG.info("Verifying sublayouts...")

    def verify_nested(
        nested_metadata, nested_key_dict, name, link_dir, path, _report
    ):
        nested_report = VerificationReport()
        try:
            nested_link = in_toto_verify(
                nested_metadata,
                nested_key_dict,
                link_dir_path=link_dir,
                step_name=name,
                inspect_timeout=inspect_timeout,
                report=nested_report,
                _step_path=path,
            )
        except Exception:
            # Preserve whatever the nested layout completed before the
            # interruption, then let the caller handle the failure.
            parent = _sublayout_parent_item(report, name, path)
            merge_sublayout_report(parent, nested_report)
            raise
        parent = _sublayout_parent_item(report, name, path)
        merge_sublayout_report(parent, nested_report)
        # A sublayout that could not even be parsed yields no summary link.
        # Return an empty placeholder so the caller can still attribute the
        # failure to this step instead of crashing on a missing link.
        return nested_link or in_toto.models.link.Link(name=name)

    chain_link_dict = verify_sublayouts(
        layout,
        steps_metadata,
        link_dir_path,
        inspect_timeout,
        report=report,
        step_paths=step_paths,
        step_order=ordered_names,
        verify_sublayout=verify_nested,
    )

    # 6. Command alignment is a soft check: record a warning, never fail.
    LOG.info("Verifying alignment of reported commands...")
    for step in layout.steps:
        item = item_by_name[step.name]
        for keyid in sorted(chain_link_dict.get(step.name, {})):
            link = chain_link_dict[step.name][keyid]
            if link.command != step.expected_command:
                message = (
                    f"Run command '{link.command}' differs from expected"
                    f" command '{step.expected_command}'"
                )
                LOG.warning("%s", message)
                item.add_issue(
                    make_issue(
                        CATEGORY_COMMAND_MISMATCH,
                        message,
                        path=step_paths[step.name],
                        severity=SEVERITY_WARNING,
                        details={"keyid": keyid},
                    )
                )

    # 7. Threshold artifact constraints (contradicting artifacts per step).
    LOG.info("Verifying threshold constraints...")
    verify_threshold_constraints(
        layout, chain_link_dict, report=report, step_paths=step_paths
    )

    # Only steps whose evidence is trustworthy may provide artifact evidence
    # to other steps. A step whose links could not be authenticated (signature
    # threshold, signature failure, unreadable metadata, failed delegated
    # layout) is excluded, so a downstream step cannot "pass" on untrusted
    # input. Its own result still reflects the violations it did produce.
    trustworthy_links = {}
    for name in ordered_names:
        if _has_trust_failure(item_by_name[name]):
            continue
        key_link_dict = chain_link_dict.get(name, {})
        if key_link_dict:
            trustworthy_links[name] = key_link_dict[min(key_link_dict)]
    reduced_chain_link_dict = trustworthy_links

    # 8. Step rules, in dependency order. A step's rules are only evaluated if
    # its evidence is authenticated and all steps it references provide usable
    # evidence; otherwise the step is undetermined rather than passed.
    LOG.info("Verifying Step rules...")
    for name in ordered_names:
        item = item_by_name[name]
        step = layout.get_step_by_name(name)
        missing_dependencies = sorted(
            dependency
            for dependency in _iter_step_dependency_names(step, layout)
            if dependency not in trustworthy_links
        )
        if name not in trustworthy_links:
            item.add_issue(
                make_issue(
                    CATEGORY_RULE_EVALUATION_ERROR,
                    "Artifact rules could not be evaluated because this step's"
                    " evidence is not trustworthy.",
                    path=step_paths[name],
                    severity=SEVERITY_UNDETERMINED,
                )
            )
            continue
        if missing_dependencies:
            item.add_issue(
                make_issue(
                    CATEGORY_RULE_EVALUATION_ERROR,
                    "Artifact rules could not be fully evaluated because"
                    " referenced step(s) do not provide trustworthy evidence:"
                    f" {', '.join(missing_dependencies)}.",
                    path=step_paths[name],
                    severity=SEVERITY_UNDETERMINED,
                    details={"untrusted_dependencies": missing_dependencies},
                )
            )
            continue

        # A single-item report scope receives all findings of this step only.
        try:
            verify_all_item_rules(
                [step],
                reduced_chain_link_dict,
                report=_item_report_scope(item),
                paths=step_paths,
            )
        except Exception as exc:  # noqa: BLE001
            if not any(
                issue.category
                in {CATEGORY_RULE_VIOLATION, CATEGORY_RULE_EVALUATION_ERROR}
                for issue in item.issues
            ):
                item.add_issue(
                    make_issue(
                        CATEGORY_RULE_EVALUATION_ERROR,
                        f"Could not evaluate artifact rules: {exc}",
                        path=step_paths[name],
                        severity=SEVERITY_UNDETERMINED,
                        details={"error": exception_chain(exc)},
                    )
                )

    # 9. Inspections. They run after all steps; a failing inspection does not
    # prevent the remaining inspections from running.
    LOG.info("Executing Inspection commands...")
    inspection_links = {}
    for inspection in layout.inspect:
        item = inspection_results[inspection.name]

        if report.has_error():
            # Do not run inspection commands on input that already failed
            # verification. The inspection stays undetermined, not passed.
            item.add_issue(
                make_issue(
                    CATEGORY_INSPECTION_SKIPPED,
                    "Inspection was not executed because step verification"
                    " failed.",
                    path=item.path,
                    severity=SEVERITY_UNDETERMINED,
                )
            )
            continue

        try:
            inspection_links.update(
                run_all_inspections(
                    _SingleInspectionLayout(inspection),
                    persist_inspection_links,
                    inspect_timeout,
                )
            )
        except Exception as exc:  # noqa: BLE001
            item.add_issue(
                make_issue(
                    CATEGORY_INSPECTION_FAILURE,
                    f"Inspection command failed: {exc}",
                    path=item.path,
                    details={"error": exception_chain(exc)},
                )
            )

    LOG.info("Verifying Inspection rules...")
    combined_links = reduced_chain_link_dict.copy()
    combined_links.update(inspection_links)
    for inspection in layout.inspect:
        item = inspection_results[inspection.name]
        if inspection.name not in inspection_links:
            continue
        try:
            verify_all_item_rules(
                [inspection],
                combined_links,
                report=_item_report_scope(item),
                paths={inspection.name: item.path},
            )
        except Exception as exc:  # noqa: BLE001
            if not any(
                issue.category
                in {CATEGORY_RULE_VIOLATION, CATEGORY_RULE_EVALUATION_ERROR}
                for issue in item.issues
            ):
                item.add_issue(
                    make_issue(
                        CATEGORY_RULE_EVALUATION_ERROR,
                        f"Could not evaluate artifact rules: {exc}",
                        path=item.path,
                        severity=SEVERITY_UNDETERMINED,
                        details={"error": exception_chain(exc)},
                    )
                )

    report.complete = True
    report.finalize()

    if report.passed:
        LOG.info("The software product passed all verification.")
    else:
        LOG.info("Verification did not pass. See the verification report.")

    summary_link = None
    if all(step.name in reduced_chain_link_dict for step in layout.steps):
        summary_link = get_summary_link(
            layout, reduced_chain_link_dict, step_name
        )
    report.summary_link = summary_link
    return summary_link


class _SingleInspectionLayout:
    """Minimal layout proxy exposing exactly one inspection.

    ``run_all_inspections`` only reads ``layout.inspect`` and resets the global
    artifact base path per inspection; running one inspection at a time lets us
    attribute command failures to the inspection that produced them.
    """

    def __init__(self, inspection):
        self.inspect = [inspection]


def verify_layout_report(  # noqa: PLR0913, PLR0917
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
    step_name="",
    persist_inspection_links=True,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """Verify a supply chain and return a complete, deterministic report.

    This is the report-driven counterpart of :func:`in_toto_verify`. Every
    step and inspection gets its own conclusion, including signer counts and
    attributed reasons for failure; a failure never prevents later steps from
    being verified.

    Malformed step references and dependency cycles are rejected before any
    verification work starts and are raised as ``LayoutReferenceError``; they
    are layout errors, not verification outcomes. Every other finding is part
    of the returned report.

    Arguments: See :func:`in_toto_verify`. ``report`` and private arguments are
    not accepted here.

    Raises:
      LayoutReferenceError: A rule references a nonexistent step, or step
          references form a cycle.

    Returns:
      A ``VerificationReport``. Its ``summary_link`` attribute holds the summary
      link that ``in_toto_verify`` would return, when one could be built.
    """
    report = VerificationReport()
    in_toto_verify(
        metadata,
        layout_key_dict,
        link_dir_path=link_dir_path,
        substitution_parameters=substitution_parameters,
        step_name=step_name,
        persist_inspection_links=persist_inspection_links,
        inspect_timeout=inspect_timeout,
        report=report,
    )
    return report
