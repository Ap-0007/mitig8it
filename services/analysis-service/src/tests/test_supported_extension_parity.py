"""The scope tier 2 scans is written down four times, and all four must agree.

The list lives in four places because four different runtimes need it and none of them
can import the others:

* `opengrep_runner.SUPPORTED_EXTENSIONS` decides what the scanner is handed.
* `prAnalysisOrchestrator.js` decides what the orchestrator fetches content for, so an
  extension missing there never reaches the scanner however willing the scanner is.
* `prodfilters.py` mirrors the orchestrator so a replay describes production rather than
  an idealised version of it.
* `action/orchestrator/pr_scope.py` is the Action's own port: it has no Node orchestrator
  to ask, so a divergence there gives the self-hosted product a different scope from the
  hosted one.

A divergence is silent in all four directions. An extension added only to the scanner
scans nothing, because no content arrives. An extension added only to the orchestrator
pays to fetch files the scanner drops. An extension added only to the replay makes the
harness report recall the product cannot deliver. One added only to the Action makes the
two products disagree about what a review covers.

The fifth candidate, `fetchPullRequestFiles` in
`services/github-service/src/services/githubInternalOperations.js`, is deliberately not
here: it filters on status and on `dist/`/`node_modules` and never on extension, so it has
no copy of this list to keep in step. `test_the_changed_file_filter_does_not_exclude_workflows`
below asserts that, because the workflow scope depends on it.

The workflow half is a path rather than an extension, so it is asserted twice: the literals
agree, and the behaviour agrees on a workflow, on ordinary YAML, and on a directory that
merely looks like one.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from opengrep_runner import (
    CODE_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    TEMPLATE_EXTENSIONS,
    WORKFLOW_DIRECTORY,
    WORKFLOW_EXTENSIONS,
    is_tier2_scannable_path,
    is_workflow_path,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
ORCHESTRATOR_JS = REPO_ROOT / "services" / "api-service" / "src" / "services" / "prAnalysisOrchestrator.js"
PRODFILTERS_PY = REPO_ROOT / "scripts" / "replay" / "prodfilters.py"
ACTION_PR_SCOPE_PY = REPO_ROOT / "action" / "orchestrator" / "pr_scope.py"
GITHUB_INTERNAL_JS = (
    REPO_ROOT / "services" / "github-service" / "src" / "services" / "githubInternalOperations.js"
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_prodfilters():
    return _load_module("prodfilters_under_test", PRODFILTERS_PY)


def _js_array(name: str) -> set[str]:
    """Read one `const <name> = [ ... ];` array of string literals out of the orchestrator.

    Parsed rather than imported: the orchestrator pulls in the database pool and the gRPC
    clients at import time, and a parity test should not need a database to answer.
    """
    source = ORCHESTRATOR_JS.read_text(encoding="utf-8")
    match = re.search(rf"const {name} = \[(.*?)\];", source, re.S)
    assert match, f"{name} is not declared in {ORCHESTRATOR_JS.name} in the form this test reads"
    return set(re.findall(r"'(\.[A-Za-z0-9]+)'", match.group(1)))


def _js_string(name: str) -> str:
    source = ORCHESTRATOR_JS.read_text(encoding="utf-8")
    match = re.search(rf"const {name} = '([^']*)';", source)
    assert match, f"{name} is not declared in {ORCHESTRATOR_JS.name} in the form this test reads"
    return match.group(1)


PRODFILTERS = _load_prodfilters()
ACTION_SCOPE = _load_module("action_pr_scope_under_test", ACTION_PR_SCOPE_PY)


class TestTheFourCopiesAgree:
    def test_code_extensions_agree(self):
        assert _js_array("TIER2_CODE_EXTENSIONS") == CODE_EXTENSIONS
        assert PRODFILTERS.TIER2_CODE_EXTENSIONS == CODE_EXTENSIONS
        assert set(ACTION_SCOPE.TIER2_CODE_EXTENSIONS) == CODE_EXTENSIONS

    def test_template_extensions_agree(self):
        assert _js_array("TIER2_TEMPLATE_EXTENSIONS") == TEMPLATE_EXTENSIONS
        assert PRODFILTERS.TIER2_TEMPLATE_EXTENSIONS == TEMPLATE_EXTENSIONS
        assert set(ACTION_SCOPE.TIER2_TEMPLATE_EXTENSIONS) == TEMPLATE_EXTENSIONS

    def test_workflow_extensions_agree(self):
        assert _js_array("TIER2_WORKFLOW_EXTENSIONS") == WORKFLOW_EXTENSIONS
        assert PRODFILTERS.TIER2_WORKFLOW_EXTENSIONS == WORKFLOW_EXTENSIONS
        assert set(ACTION_SCOPE.TIER2_WORKFLOW_EXTENSIONS) == WORKFLOW_EXTENSIONS

    def test_workflow_directory_agrees(self):
        assert _js_string("TIER2_WORKFLOW_DIRECTORY") == WORKFLOW_DIRECTORY
        assert PRODFILTERS.TIER2_WORKFLOW_DIRECTORY == WORKFLOW_DIRECTORY
        assert ACTION_SCOPE.TIER2_WORKFLOW_DIRECTORY == WORKFLOW_DIRECTORY

    def test_the_workflow_half_is_not_folded_into_the_extension_sets(self):
        """`.yml` admitted by extension would put the workflow rules over every manifest,
        compose file and other provider's CI config in the repository, and would make the
        product fetch all of them to find the few that are workflows."""
        assert WORKFLOW_EXTENSIONS & SUPPORTED_EXTENSIONS == set()

    def test_the_unions_agree(self):
        """What actually gates a file is the union, so the union is asserted too: the two
        halves could each be wrong in a way that cancels out."""
        combined = _js_array("TIER2_CODE_EXTENSIONS") | _js_array("TIER2_TEMPLATE_EXTENSIONS")
        assert combined == SUPPORTED_EXTENSIONS
        assert PRODFILTERS.TIER2_SUPPORTED_EXTENSIONS == SUPPORTED_EXTENSIONS

    def test_the_two_halves_do_not_overlap(self):
        assert CODE_EXTENSIONS & TEMPLATE_EXTENSIONS == set()

    def test_every_entry_is_a_lowercase_dotted_suffix(self):
        """`should_fetch_content` lowercases the suffix before the lookup, so an uppercase
        entry here would be unreachable."""
        for extension in SUPPORTED_EXTENSIONS:
            assert extension.startswith("."), extension
            assert extension == extension.lower(), extension


class TestTheOrchestratorActuallyGatesOnIt:
    """Parity between the lists is worth nothing if the replay stopped consulting them."""

    @pytest.mark.parametrize("path", ["app/views/layout.html", "views/products.ejs", "src/App.vue"])
    def test_a_template_file_is_fetched_for_tier2(self, path):
        assert PRODFILTERS.should_fetch_content(path) is True

    @pytest.mark.parametrize("path", ["README.md", "assets/logo.svg", "package-lock.json"])
    def test_an_unsupported_file_is_not_fetched(self, path):
        assert PRODFILTERS.should_fetch_content(path) is False

    def test_the_existing_exclusions_still_apply_to_templates(self):
        assert PRODFILTERS.should_fetch_content("node_modules/x/views/a.ejs") is False
        assert PRODFILTERS.should_fetch_content("dist/index.html") is False


# The paths that decide the workflow scope, and what every copy must answer for each.
WORKFLOW_SCOPE_CASES = [
    (".github/workflows/ci.yml", True),
    (".github/workflows/release.yaml", True),
    ("packages/api/.github/workflows/ci.yml", True),
    (".GitHub/Workflows/CI.yml", True),
    # Ordinary YAML. None of the workflow rules is true of any of these, and fetching them
    # would be paying for content nothing reads.
    ("docker-compose.yml", False),
    ("k8s/deployment.yaml", False),
    (".mitig8it.yml", False),
    (".circleci/config.yml", False),
    (".github/dependabot.yml", False),
    ("config/workflows/pipeline.yml", False),
    # A directory that merely ends in the right name. The segment is matched, not the suffix.
    ("vendor/notgithub/workflows/ci.yml", False),
]


class TestTheWorkflowScopeIsThePathNotTheExtension:
    @pytest.mark.parametrize("path,expected", WORKFLOW_SCOPE_CASES)
    def test_the_scanner_gate_agrees(self, path, expected):
        assert is_tier2_scannable_path(path) is expected, path
        assert is_workflow_path(path) is expected, path

    @pytest.mark.parametrize("path,expected", WORKFLOW_SCOPE_CASES)
    def test_the_replay_gate_agrees(self, path, expected):
        assert PRODFILTERS.should_fetch_content(path) is expected, path
        assert PRODFILTERS.is_workflow_path(path) is expected, path

    @pytest.mark.parametrize("path,expected", WORKFLOW_SCOPE_CASES)
    def test_the_action_gate_agrees(self, path, expected):
        assert ACTION_SCOPE.should_fetch_full_file_content({"path": path}) is expected, path
        assert ACTION_SCOPE.is_workflow_path(path) is expected, path

    def test_the_source_extensions_are_unaffected(self):
        """The workflow branch must widen the scope and nothing else."""
        for path in ("src/app.py", "views/products.ejs", "src/App.vue"):
            assert is_tier2_scannable_path(path) is True
            assert is_workflow_path(path) is False


class TestTheChangedFileFilterDoesNotExcludeWorkflows:
    """The scanner can only read a file the github-service forwarded.

    `fetchPullRequestFiles` has no extension list, which is why it is not in the parity set
    above, but it does have two path exclusions and a status filter. A workflow passes all
    three; this asserts it, because the whole workflow category depends on it and the
    dependency is otherwise invisible from here.
    """

    def test_the_only_path_exclusions_are_dist_and_node_modules(self):
        source = GITHUB_INTERNAL_JS.read_text(encoding="utf-8")
        match = re.search(
            r"const scoped = files\s*\n(?P<body>(?:\s*\.filter\([^\n]*\n)+)", source
        )
        assert match, "the scoped-files filter in fetchPullRequestFiles has changed shape"
        body = match.group("body")
        assert "'added', 'modified', 'renamed'" in body
        assert "startsWith('dist/')" in body
        assert "includes('node_modules')" in body
        # Anything else would be a filter this test has not read, and a workflow might not
        # survive it.
        assert body.count(".filter(") == 2, body

    def test_a_workflow_path_survives_those_exclusions(self):
        path = ".github/workflows/ci.yml"
        assert not path.startswith("dist/")
        assert "node_modules" not in path
        assert PRODFILTERS.scoped_files([{"filename": path, "status": "modified"}]) == [
            {"filename": path, "status": "modified"}
        ]
