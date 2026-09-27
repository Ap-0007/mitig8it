"""`workflow_hardening`: the two patches it can build, and why neither of them ships yet.

This family is the first one whose repair cannot be proven by running anything. A regression
test shows a repair by failing on the original tree and passing on the patched one, and there is
no such test for a workflow: the artefact is a document GitHub interprets, there is no module to
load, no call to observe, and running it would mean running CI. So the family declares
`static_assertion` verification -- the rule fires on the file before the change and not after it,
and nothing else in the file changed -- which is the level `feat/static-assertion-verification`
is adding.

Until that level exists, every candidate of this family is refused by name. That is asserted here
as loudly as the patches are, because the failure mode this protects against is not a wrong patch
but a right one published as though something had checked it.

The two shapes are the only two that are an edit rather than a decision. Moving a build out of
`pull_request_target`, dropping a write scope, replacing a self-hosted runner: each of those
changes what the workflow does, and a patch cannot choose that for a maintainer.
"""
from __future__ import annotations

import pytest

from src.families import (
    FAMILY_VERIFICATION,
    SANDBOX_PROVEN_FAMILIES,
    SANDBOX_REGRESSION_TEST,
    STATIC_ASSERTION,
    WORKFLOW,
    WORKFLOW_HARDENING,
    declares_static_assertion,
    family_assertion,
    family_supported,
    family_verification,
    is_workflow_path,
    language_of_path,
    rule_family,
)
from src.gates import (
    STATIC_ASSERTION_UNAVAILABLE_MESSAGE,
    static_assertion_level_available,
    static_gate,
)
from src.git_tree import compute_tree_oid
from src.models import GitTreeEntry, RepairRequest
from src.retrieval import Snapshot
from src.sites import SiteError, workflow_step_for_line
from src.templates import (
    ACTION_DIGEST_UNRESOLVED,
    TemplateFallback,
    environment_variable_name,
    generate_template,
)
from src.verification.verifier import (
    SANDBOX_VERIFICATION_LEVELS,
    STATIC_ASSERTION_VERIFICATION_LEVEL,
    VERIFICATION_LEVELS,
)
from tests.conftest import git_blob

WORKFLOW_PATH = ".github/workflows/triage.yml"

INJECTION_WORKFLOW = """\
name: triage
on:
  issue_comment:
    types: [created]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: record the comment
        run: |
          set -eu
          echo "${{ github.event.comment.body }}" >> notes.md
      - name: label from the title
        id: label
        env:
          RUNNER: ubuntu
        run: echo ${{ github.event.issue.title }}
"""

UNPINNED_WORKFLOW = """\
name: coverage
on: push
jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codecov/codecov-action@v5
      - uses: qltysh/qlty-action/coverage@v2 # keep in step with qlty.toml
      - uses: some-org/pinned@0123456789abcdef0123456789abcdef01234567 # v1.2.3
"""

DIGEST = "d6f2f4c6cbd7e1e1c9f0e8a4b3c2d1e0f9a8b7c6"


def _snapshot(request_payload: dict, source: str, findings: list[dict], path: str = WORKFLOW_PATH):
    entries = [GitTreeEntry(path=path, mode="100644", type="blob", sha=git_blob(source))]
    payload = dict(request_payload)
    payload["tree_entries"] = [entry.model_dump() for entry in entries]
    payload["head_tree_oid"] = compute_tree_oid(entries)
    payload["files"] = [{"path": path, "content": source, "sha": git_blob(source)}]
    payload["findings"] = findings
    request = RepairRequest.model_validate(payload)
    return Snapshot(request), request


def _injection_finding(line: int, path: str = WORKFLOW_PATH) -> dict:
    return {
        "snapshot_id": f"gha-inj-{line}",
        "rule_id": "opengrep.cwe-78.gha-run-untrusted-interpolation",
        "cwe_id": "CWE-78",
        "internal_type": "workflow_script_injection",
        "category": "CI/CD",
        "file_path": path,
        "line_start": line,
        "line_end": line,
    }


def _unpinned_finding(line: int, digest: str | None = DIGEST, path: str = WORKFLOW_PATH) -> dict:
    finding = {
        "snapshot_id": f"gha-pin-{line}",
        "rule_id": "opengrep.cwe-1357.gha-third-party-action-unpinned",
        "cwe_id": "CWE-1357",
        "internal_type": "unpinned_action_reference",
        "category": "CI/CD",
        "file_path": path,
        "line_start": line,
        "line_end": line,
    }
    if digest is not None:
        finding["evidence_details"] = {"extra": {"resolved_action_digest": digest}}
    return finding


class TestFamilyResolution:
    @pytest.mark.parametrize(
        "path,expected",
        [
            (".github/workflows/ci.yml", True),
            (".github/workflows/ci.yaml", True),
            ("packages/api/.github/workflows/ci.yml", True),
            ("docker-compose.yml", False),
            ("k8s/deployment.yaml", False),
            ("vendor/notgithub/workflows/ci.yml", False),
        ],
    )
    def test_only_a_workflow_path_is_the_workflow_language(self, path, expected):
        assert is_workflow_path(path) is expected
        assert (language_of_path(path) == WORKFLOW) is expected

    def test_the_family_is_supported_for_workflows_and_nothing_else(self):
        assert family_supported(WORKFLOW_HARDENING, WORKFLOW)
        assert not family_supported(WORKFLOW_HARDENING, "javascript")
        assert not family_supported(WORKFLOW_HARDENING, "python")
        for family in SANDBOX_PROVEN_FAMILIES:
            assert not family_supported(family, WORKFLOW), family

    def test_cwe_78_on_a_workflow_is_not_the_command_family(self, request_payload):
        """The shell-injection rule declares CWE-78, which `command_arguments` is derived from.

        If the CWE won, a workflow would be handed to the template that rewrites a
        `child_process` call into an argument list, and there is no such call in a workflow.
        """
        _, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(12)])
        assert rule_family(request.findings[0]) == WORKFLOW_HARDENING

    def test_the_unpinned_rule_resolves_to_the_family_too(self, request_payload):
        _, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(8)])
        assert rule_family(request.findings[0]) == WORKFLOW_HARDENING


class TestTheFamilyVerifiesByStaticAssertion:
    def test_the_declaration(self):
        assert family_verification(WORKFLOW_HARDENING) == STATIC_ASSERTION
        for family in SANDBOX_PROVEN_FAMILIES:
            assert FAMILY_VERIFICATION[family] == SANDBOX_REGRESSION_TEST, family

    def test_there_is_no_harness_assertion_for_it(self):
        """A caller reaching for one is about to build a proof for something a proof cannot
        describe, so the table answers None rather than a plausible-looking string."""
        assert family_assertion(WORKFLOW_HARDENING, WORKFLOW) is None
        assert family_assertion(WORKFLOW_HARDENING, "python") is None

    def test_the_level_exists_and_the_family_declares_it(self):
        """The switch was one entry in one set, and the level has since been implemented.

        `VERIFICATION_LEVELS` is every level a candidate may carry, so the gate's question now
        answers true and this family is on. The set a sandbox driver may claim is the narrower
        `SANDBOX_VERIFICATION_LEVELS`, which still excludes this level: it is produced by the
        verifier from a scanner answer, never reported by a driver.
        """
        assert STATIC_ASSERTION_VERIFICATION_LEVEL == "static_assertion"
        assert STATIC_ASSERTION_VERIFICATION_LEVEL in VERIFICATION_LEVELS
        assert STATIC_ASSERTION_VERIFICATION_LEVEL not in SANDBOX_VERIFICATION_LEVELS
        assert static_assertion_level_available() is True
        assert declares_static_assertion(WORKFLOW_HARDENING) is True


class TestTheGateNoLongerRefusesTheFamily:
    def test_a_workflow_finding_reaches_the_agent(self, request_payload):
        """The level it needs exists, so the one gate this family had opens.

        Nothing else in the gate applies to a workflow: there is no package manifest to prove, no
        shell string and no compiled program.
        """
        snapshot, request = _snapshot(
            request_payload, INJECTION_WORKFLOW, [_injection_finding(12), _injection_finding(17)]
        )
        for finding in request.findings:
            assert static_gate(snapshot, finding, WORKFLOW_HARDENING, WORKFLOW) is None

    def test_the_reason_says_what_is_missing_and_that_the_finding_still_arrives(self):
        """Kept, because the refusal is still reachable: an operator who sets
        `allow_static_assertion_verification` false, or a deployment with no analysis service to
        re-run the rule, is back in exactly the state this message describes."""
        assert "static assertion" in STATIC_ASSERTION_UNAVAILABLE_MESSAGE
        assert "not available yet" in STATIC_ASSERTION_UNAVAILABLE_MESSAGE
        assert "withheld" in STATIC_ASSERTION_UNAVAILABLE_MESSAGE
        assert "reported" in STATIC_ASSERTION_UNAVAILABLE_MESSAGE

    def test_the_gate_closes_again_if_the_level_is_ever_withdrawn(self, request_payload, monkeypatch):
        """The switch reads one set, and this is the test that says so, from the other side.

        A workflow patch nothing checked must not be published as if something had, so if the
        level ever stops being a level a candidate may carry, the family is refused by name again
        rather than shipping unverified.
        """
        monkeypatch.setattr(
            "src.gates.VERIFICATION_LEVELS",
            VERIFICATION_LEVELS - {STATIC_ASSERTION_VERIFICATION_LEVEL},
        )
        snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(12)])
        gate = static_gate(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert gate is not None, "a workflow patch was allowed through with no possible proof"
        assert gate[0] == "static_assertion_verification_unavailable"
        assert gate[1] == STATIC_ASSERTION_UNAVAILABLE_MESSAGE

    def test_the_other_families_are_unaffected(self, request_payload):
        """The new branch is keyed on the family's verification mode, not on the language, so it
        must not swallow the gates the sandbox families already had."""
        source = "const cp = require('child_process');\nfunction f(h) { return cp.exec(`ping ${h} | tee log`); }\n"
        snapshot, request = _snapshot(
            request_payload,
            source,
            [{"snapshot_id": "cmd-1", "rule_id": "cwe-78.js-exec-interpolated", "cwe_id": "CWE-78", "file_path": "src/a.js", "line_start": 2, "line_end": 2}],
            path="src/a.js",
        )
        gate = static_gate(snapshot, request.findings[0], "command_arguments", "javascript")
        assert gate is not None and gate[0] == "shell_pipeline_unsupported"


class TestTheStepSiteModel:
    def test_a_block_scalar_step_spans_to_the_next_item(self):
        step = workflow_step_for_line(INJECTION_WORKFLOW, 12)
        assert (step.start_line, step.end_line) == (9, 12)
        assert step.key_indent == 8
        assert step.env_line is None

    def test_a_step_with_an_env_block_reports_it(self):
        step = workflow_step_for_line(INJECTION_WORKFLOW, 17)
        assert step.start_line == 13
        assert step.env_line == 15
        assert step.env_indent == 8

    def test_a_line_outside_any_step_is_refused(self):
        with pytest.raises(SiteError) as excinfo:
            workflow_step_for_line(INJECTION_WORKFLOW, 2)
        assert excinfo.value.code == "workflow_step_not_found"


class TestEnvironmentVariableNames:
    @pytest.mark.parametrize(
        "expression,expected",
        [
            ("github.event.comment.body", "COMMENT_BODY"),
            ("github.event.issue.title", "ISSUE_TITLE"),
            ("github.event.pull_request.title", "PR_TITLE"),
            ("github.event.pull_request.head.ref", "HEAD_REF"),
            ("github.head_ref", "HEAD_REF"),
            ("github.event.head_commit.message", "HEAD_COMMIT_MESSAGE"),
        ],
    )
    def test_the_name_says_where_the_value_came_from(self, expression, expected):
        assert environment_variable_name(expression) == expected

    def test_the_name_is_always_a_legal_shell_identifier(self):
        for expression in ("github.event.pages[0].page_name", "  ", "github.event.commits[0].author.email"):
            name = environment_variable_name(expression)
            assert name and not name[0].isdigit()
            assert all(character.isalnum() or character == "_" for character in name)
            assert name == name.upper()


class TestTheEnvironmentBindingPatch:
    def test_a_block_scalar_script_gets_a_new_env_block(self, request_payload):
        snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(12)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        insertion, rewrite = patch.changes
        assert insertion["start_line"] == 9
        assert insertion["replacement_lines"] == [
            "      - name: record the comment",
            "        env:",
            "          COMMENT_BODY: ${{ github.event.comment.body }}",
        ]
        assert rewrite["start_line"] == 12
        assert rewrite["replacement_lines"] == ['          echo "$COMMENT_BODY" >> notes.md']

    def test_an_existing_env_block_is_extended_rather_than_duplicated(self, request_payload):
        snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(17)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        insertion, rewrite = patch.changes
        assert insertion["start_line"] == 15
        assert insertion["replacement_lines"] == [
            "        env:",
            "          ISSUE_TITLE: ${{ github.event.issue.title }}",
        ]
        assert rewrite["replacement_lines"] == ['        run: echo "$ISSUE_TITLE"']

    def test_the_authors_own_quotes_are_not_doubled(self, request_payload):
        """`echo "${{ x }}"` must become `echo "$X"`, not `echo ""$X""`."""
        snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(12)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert '""' not in patch.changes[1]["replacement_lines"][0]

    def test_two_interpolations_on_one_line_get_two_bindings(self, request_payload):
        source = (
            "name: t\n"
            "on: issue_comment\n"
            "jobs:\n"
            "  t:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ github.event.issue.title }} ${{ github.event.comment.body }}\n"
        )
        snapshot, request = _snapshot(request_payload, source, [_injection_finding(7)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        insertion, rewrite = patch.changes
        assert insertion["replacement_lines"][1:] == [
            "        env:",
            "          ISSUE_TITLE: ${{ github.event.issue.title }}",
            "          COMMENT_BODY: ${{ github.event.comment.body }}",
        ]
        assert rewrite["replacement_lines"] == ['      - run: echo "$ISSUE_TITLE" "$COMMENT_BODY"']

    def test_the_patched_line_no_longer_carries_an_interpolation(self, request_payload):
        """The rule matches an interpolation inside a script. If the patched line still had one
        the static assertion could never pass, so this is the property the level will check."""
        for line in (12, 17):
            snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [_injection_finding(line)])
            patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
            for replacement in patch.changes[-1]["replacement_lines"]:
                assert "${{" not in replacement


class TestThePinningPatch:
    def test_a_tag_is_replaced_by_the_resolved_digest_with_the_tag_kept(self, request_payload):
        snapshot, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(8)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert not isinstance(patch, TemplateFallback), getattr(patch, "reason", None)
        assert patch.changes[0]["replacement_lines"] == [
            f"      - uses: codecov/codecov-action@{DIGEST} # v5"
        ]

    def test_an_existing_comment_is_kept_and_the_tag_added_to_it(self, request_payload):
        snapshot, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(9)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert patch.changes[0]["replacement_lines"] == [
            f"      - uses: qltysh/qlty-action/coverage@{DIGEST} "
            "# keep in step with qlty.toml (v2)"
        ]

    def test_a_reference_that_is_already_a_digest_is_not_touched(self, request_payload):
        snapshot, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(10)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "action_already_pinned"

    def test_a_digest_nobody_resolved_is_refused_rather_than_invented(self, request_payload):
        """The digest is resolved at analysis time, where the product still has the network. The
        repair sandbox has none, so a template that guessed would be changing which code runs."""
        snapshot, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(8, digest=None)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == ACTION_DIGEST_UNRESOLVED

    @pytest.mark.parametrize("digest", ["v5", "0123456789abcdef", "z" * 40, ""])
    def test_a_malformed_digest_is_refused_too(self, request_payload, digest):
        snapshot, request = _snapshot(request_payload, UNPINNED_WORKFLOW, [_unpinned_finding(8, digest=digest)])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == ACTION_DIGEST_UNRESOLVED


class TestTheShapesThatAreNotAnEdit:
    @pytest.mark.parametrize(
        "rule_id,internal_type",
        [
            ("opengrep.cwe-829.gha-untrusted-checkout-privileged-trigger", "untrusted_code_checkout"),
            ("opengrep.cwe-829.gha-build-step-under-privileged-trigger", "untrusted_build_execution"),
            ("opengrep.cwe-732.gha-permissions-write-all", "excessive_workflow_permissions"),
            ("opengrep.cwe-522.gha-persist-credentials-on-untrusted-checkout", "workflow_credential_persistence"),
            ("opengrep.cwe-200.gha-secret-in-untrusted-checkout-job", "workflow_secret_exposure"),
            ("opengrep.cwe-668.gha-self-hosted-runner-fork-trigger", "self_hosted_runner_exposure"),
        ],
    )
    def test_they_produce_no_patch_and_say_why(self, request_payload, rule_id, internal_type):
        finding = {**_injection_finding(12), "rule_id": rule_id, "internal_type": internal_type}
        snapshot, request = _snapshot(request_payload, INJECTION_WORKFLOW, [finding])
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "workflow_shape_not_templated"

    def test_a_yaml_file_that_is_not_a_workflow_is_refused(self, request_payload):
        snapshot, request = _snapshot(
            request_payload,
            INJECTION_WORKFLOW,
            [_injection_finding(12, path="deploy/triage.yml")],
            path="deploy/triage.yml",
        )
        patch = generate_template(snapshot, request.findings[0], WORKFLOW_HARDENING, WORKFLOW)
        assert isinstance(patch, TemplateFallback)
        assert patch.reason == "not_a_workflow_path"
