# Analysis Service

FastAPI service that analyzes changed pull request files.

## Responsibilities

- Accept changed-file PR payloads from the API service.
- Filter scanner rule fixtures. Test code is scanned, not filtered: `src/test_code_scope.py` recognizes `tests/`, `__tests__/`, `test_*`, `*.test.*`, and `*.spec.*`, marks those findings `in_test_code` in `evidence_details.extra`, preserves the scanner's `original_severity`, and reports them as `info` so they are visible without failing a check run.
- Run Tier 1 regex and dependency-risk checks.
- Run Tier 2 OpenGrep rules, in batches bounded by `OPENGREP_BATCH_MAX_FILES` and `OPENGREP_BATCH_MAX_BYTES`. A file larger than the byte budget gets its own batch, and a batch that fails outright raises, so the tier fails closed rather than returning partial results.
- Classify the scanner's own errors instead of failing on all of them. A warning-level parse problem in one file (`Lexical error`, `Syntax error`, `Partial parsing`) or a per-file resource ceiling (`Timeout`, `Out of memory`, `Too many matches`) keeps the findings from every other file and is reported as an entry in `analysis_limitations` naming the file, the kind of gap, and the line. Anything at error level that is not attributable to a file, such as an invalid rule or a config error, still fails the tier closed, now with the error types, paths, message prefixes, and the stderr tail in the raised message.
- Run optional Tier 3 LLM triage when configured. The Gemini default is `gemini-2.5-flash-lite` and the OpenAI default is `gpt-4o-mini`. Triage failure is non-blocking, and every log line and error body on those paths passes through `redact()` so a misconfigured provider call cannot print credentials.
- Build remediation patch metadata when possible. The repairs themselves are the remediation service's job, not this one's.
- Normalize, cluster, and return finding objects.
- Expose health and Prometheus metrics.

The blocking analysis routes are synchronous handlers, so FastAPI runs them in its threadpool and `/health` does not wait behind a scan. `POST /analyze/pr` runs tier 1 and tier 2 concurrently on a two-worker pool and merges by tier rather than by completion order, so fingerprints and clustering stay stable.

## Rule posting policy

A finding the product cannot stand behind must not be posted. Every tier 1 rule in `src/security_rules.py` therefore declares two things:

- `precision`, either `measured` or `unmeasured`. `measured` means someone read this rule's output on a real corpus and wrote down what they found, in `precision_evidence`. `unmeasured` means nobody has, which is the honest default.
- `posting`, either `post` or `quarantine`.

A **quarantined** rule still runs. Its matches are counted in `codesentry_analysis_quarantined_findings_total` and returned as `quarantined_findings` (a count per rule) on the tier 1 and combined responses, so the replay harness and the metrics can keep measuring it. What it does not do is arrive: `partition_by_posting_policy` in `src/main.py` is the single place a quarantined finding is removed, and it removes it before the response is built. Nothing downstream needs to know the policy exists. Nothing is posted to GitHub, nothing reaches the check summary, and nothing is handed to remediation, because the finding is not there.

The quarantine is not a deletion. A rule is re-enabled individually, with evidence, by:

1. fixing it, and showing the fix on the lines that were wrong. The false positives the September 2026 replay read by hand live in `benchmarks/tier1-precision/cases.json`;
2. adding its cases to that set, including the true positives it must keep finding;
3. running the gate, `src/tests/test_tier1_precision_benchmark.py`;
4. flipping `posting` to `post` and writing what was measured into `precision_evidence`.

Two structural rules back this up, both enforced by `src/tests/test_rule_posting_policy.py`:

- **A negative condition goes in `exclusion`, not in a lookahead.** `find_ineffective_lookaheads()` in `security_rules.py` is a static check over every regex tier 1 runs. It flags a negative lookahead that an unbounded greedy quantifier precedes with no required token in between, because the engine can always satisfy such a lookahead by letting the quantifier consume to the end of the line. A rule with that shape silently degrades to its leading alternation. `exclusion` is a second pass over the matched line, where backtracking cannot defeat it.
- **Tier 1 does not read comments.** `src/comment_stripper.py` blanks line comments, block comments, JSDoc, Ruby `=begin` blocks and Python docstrings for JavaScript, TypeScript, Go, Java, C#, PHP, Ruby and Python before any regex runs, keeping line numbers and column offsets so a finding still quotes the author's text. It never strips inside a string literal, and an unmodelled extension is not touched at all. A rule can also opt out of seeing string literal bodies with `reads_string_literals=False`; the credential rule keeps them, because a secret lives in a string.

## Tier 1 budget

Tier 1 runs every rule over every changed line, and on the largest payload the caps still allow (200 files of 75 kB) that measured 50 s against the orchestrator's 30 s budget. It is now bounded twice:

- `TIER1_BUDGET_SECONDS` (default 20) is the whole pass;
- `TIER1_FILE_BUDGET_SECONDS` (default 2) is one file.

Exceeding either stops that much of the work, keeps the findings already made, and appends a `{kind: "budget", path, message}` entry to `analysis_limitations` on the response. A partial tier 1 that says how partial it was is worth more than a blown deadline.

## Local Development

```bash
cd services/analysis-service
pip install -r src/requirements.txt
uvicorn src.main:app --reload --port 8001
```

For standalone runs, export the root `.env` first:

```bash
set -a
source .env
set +a
```

## Tests

```bash
cd services/analysis-service/src
pip install -r requirements-test.txt
pytest tests -q
```

## Main Endpoints

- `GET /`
- `GET /health`
- `GET /metrics`
- `POST /analyze/pr`
- `POST /analyze/pr/tier1`
- `POST /analyze/pr/tier2`
- `POST /analyze/pr/tier3`

Analysis requests and metrics require `x-internal-secret`. The expected value is `ANALYSIS_SERVICE_INTERNAL_SECRET` when set, otherwise `GITHUB_SERVICE_INTERNAL_SECRET`.

## Key Environment

- `GITHUB_SERVICE_INTERNAL_SECRET`
- `ANALYSIS_SERVICE_INTERNAL_SECRET`
- `LLM_PROVIDER`
- `LLM_MODEL` / `LLM_TRIAGE_MODEL`
- `LLM_API_KEY`
- `GEMINI_API_KEY` / `OPENAI_API_KEY` provider-specific local fallbacks
- `FRONTEND_URL`
- `ANALYSIS_CACHE_TTL_DAYS`
- `OPENGREP_BATCH_MAX_FILES` / `OPENGREP_BATCH_MAX_BYTES` batch bounds for tier 2
- `TIER1_BUDGET_SECONDS` total tier 1 wall clock, default 20
- `TIER1_FILE_BUDGET_SECONDS` per-file tier 1 wall clock, default 2
- `WORKFLOW_ACTION_DIGEST_LOOKUP` off unless set: allows one GitHub API request per distinct action
  reference, to resolve the commit digest the pinning repair needs
- `WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN` optional bearer token for that lookup

For the full env contract, see [environment.md](../getting-started/environment.md).

## Tier 2: the rule set and the posting policy

The AST rules live in `src/opengrep_rules/*.yml`. JavaScript, TypeScript and Python are covered
by 116 rules: 25 that predate the coverage work, and 91 in `javascript_coverage.yml` and
`python_coverage.yml`. Templates add 9 more in `template_coverage.yml`, and GitHub Actions
workflows add 9 in `workflow_coverage.yml`.

### Where the rules come from

Every rule is written in this repository. No rule is copied or adapted from a public rule
library, because the two obvious ones cannot be used in a paid service: `opengrep-rules` is
LGPL-2.1 **plus the Commons Clause**, which removes the right to sell a service whose value
derives substantially from the rules, and `semgrep-rules` is under the Semgrep Rules License
v1.0, which permits internal business use only and forbids making the rules available as a
service. The reading, with the licence text, is in
[third-party-rules.md](../legal/third-party-rules.md), along with the four steps to follow
before importing a rule from anywhere.

### What a rule must declare

`tests/test_tier2_rule_metadata.py` enforces this on every rule in the two coverage files:

- `cwe`, a `severity` the scanner understands, a `confidence`, and at least one language.
- `internal_type`, from `taxonomy.CANONICAL_INTERNAL_TYPES`. This is what the product groups,
  deduplicates and reports on, so a rule that passes its own check id makes a category of one
  that nothing else can join. Adding a value to that set is a deliberate product decision.
- `family`, when the finding is repairable, and only when the rule's CWE is the one the
  remediation service derives that family from. The engine reads the CWE, not this key, so a
  rule that declared a family its CWE does not produce would be handed to the engine as
  something else.
- `posting`, which is `post` or `quarantine`.
- `precision_evidence`, when someone has measured the rule on a corpus. It must name the
  corpus or the write-up, because a precision claim nobody can re-run is an opinion.

### The posting policy

A rule posts only on evidence. It may post when its labelled precision on a real corpus is at
least 0.8 over at least three labelled findings, or when it produced no findings on the corpus
**and** its pattern is a sink-only match with a clear taxonomy that makes no data-flow
assumption. Everything else is quarantined, and a quarantined rule must carry
`posting_evidence` saying what was measured, because that is what lets the next person
re-enable it.

A quarantined rule still runs and its findings are still counted, in the response's
`quarantined_findings` map and in `codesentry_analysis_quarantined_findings_total`. What it
does not do is reach a reviewer. The removal happens in exactly one place,
`main.partition_by_posting_policy`, which both tiers go through, so the api-service needs no
knowledge of the policy: the findings simply do not arrive, nothing is posted to GitHub,
nothing is counted in the check summary, and nothing is handed to remediation.

The policy is one policy, not a tier 2 one. Tier 1 declares the same states on the rule
object in `security_rules.py` (`precision`, `posting`, `precision_evidence`), and
`main.QUARANTINED_RULE_IDS` is the union of the two declarations, so a suppression, a metric
or a reviewer never has to ask which tier a rule came from.

Seven rules are quarantined today. Two are the workflow rules
`cwe-732.gha-write-permission-under-privileged-trigger`, whose measured precision is 0.00 over ten
hand-read findings, and `cwe-668.gha-self-hosted-runner-fork-trigger`, whose claim holds only if
the repository is public; both are in
[workflow-tampering-2026-09.md](../validation/workflow-tampering-2026-09.md). The other five: four
tier 2 rules, whose measurement is in
[tier2-coverage-2026-09.md](../validation/tier2-coverage-2026-09.md), and the tier 1 rule
`path.traversal.user_path`, whose measurement is in
[vulnerable-corpus-2026-09.md](../validation/vulnerable-corpus-2026-09.md). The same corpus
gave 18 posting tier 2 rules a `precision_evidence` line.

### Re-enabling a quarantined rule

1. Narrow the pattern so the shape it was wrong about no longer matches.
2. Add that exact line to `benchmarks/tier2-precision/cases.json` as a no-finding case, with
   the repository and pull request it came from, and keep the rule's true-positive fixture.
3. Re-run the replay, or the vulnerable-corpus snapshot with `--include-quarantined`, and
   adjudicate what it now produces.
4. Change `posting` to `post` and replace `posting_evidence` with the new measurement.

A rule can also earn its way back without a pattern change, by being measured on code that
contains its shape: `scripts/replay/replay.py --snapshot --include-quarantined` keeps a
quarantined rule's findings, and `scripts/replay/score.py` reports them separately from what
posts. Three adjudicated findings at 0.8 or better is the bar, and it is a real bar:
`cwe-489.py-debug-constant-true` has two, both confirming the quarantine reason was wrong,
and it still cannot come back.

### Workflow tampering, and how it is scoped

`workflow_coverage.yml` holds nine rules for GitHub Actions workflows: an untrusted checkout under
`pull_request_target` or `workflow_run`, a build or test step under `pull_request_target`, an
interpolation of attacker-controlled event data inside a `run:` script, a third-party action
referenced by tag or branch rather than a commit digest, `permissions: write-all`, a write scope
under a privileged trigger, `persist-credentials: true` on an untrusted checkout, a repository
secret handed to a job that has checked out untrusted code, and a self-hosted runner in a workflow
a fork can trigger. Seven post and two are quarantined; the measurement is in
[workflow-tampering-2026-09.md](../validation/workflow-tampering-2026-09.md).

This is the first category whose scope is a **path** rather than an extension, and the reason is
worth stating because it is the whole of the design.

`.yml` is the most common configuration extension there is. A repository's Kubernetes manifests,
its Helm values, its `docker-compose.yml`, another provider's CI config and its own `.mitig8it.yml`
are all YAML, and `run:`, `ref:` and `permissions:` mean something different in every one of them.
Admitting `.yml` to `SUPPORTED_EXTENSIONS` would have put nine rules over all of that, and would
also have made the product fetch the content of every YAML file in every pull request in order to
find the handful that are workflows.

So the gate is `is_tier2_scannable_path` in `src/test_code_scope.py`: a source extension, a
template extension, or `.yml`/`.yaml` under a `.github/workflows/` path segment. `WORKFLOW_EXTENSIONS`
is deliberately disjoint from `SUPPORTED_EXTENSIONS`, and `tests/test_supported_extension_parity.py`
asserts that it stays that way.

The scope is written down four times, because four runtimes need it and none can import the others:
here, in `prAnalysisOrchestrator.js`, in `scripts/replay/prodfilters.py`, and in
`action/orchestrator/pr_scope.py`. The parity test compares all four on the literals and on the
behaviour, over a workflow, ordinary YAML, and a directory that merely ends in `github/workflows`.
Two dependencies that used to be invisible are asserted there too: the github-service's
changed-file filter has no extension list, only a status filter and two path exclusions, and a
workflow survives all three; and `scripts/replay/corpus.py` used to skip every dotted directory,
which would have made a snapshot report zero workflow findings however many a tree contained.

The rules are then scoped a second time, independently. They are `generic` rules, and a `generic`
rule with no `paths: include` reads every file in the batch, so each one includes exactly
`.github/workflows/*.yml` and `.github/workflows/*.yaml`.
`tests/test_workflow_rules_are_path_scoped.py` asserts the includes and then runs the whole file
through the real scanner over a document that carries every shape, at a workflow path and at two
ordinary YAML paths, because a metadata assertion would not catch a scanner whose glob semantics
changed.

Most of the patterns are a single `pattern-regex`, which is unusual here and deliberate. What these
rules express is a relation between a trigger at the top of the document and a step forty lines
below it, and a YAML pattern cannot state "this key is in the same document as that key". Each
pattern names the trigger, skips forward, and uses PCRE's `\K` to move the reported match onto the
step, so the finding lands on the line a reviewer has to change rather than on the `on:` block.
`pattern-inside: "run: ..."` was tried and is recorded at the top of the rule file as the wrong
tool: in `generic` mode `...` has no notion of a YAML block, so it ran past a single-line
`- run: npm i` into the next step's `if:` line and produced ten false findings.

One finding carries a fact the repair side cannot get for itself. The pinning repair needs the
commit an action's tag currently resolves to, and the repair sandbox has no egress by design, so
`src/workflow_action_digest.py` resolves it here and puts it on the finding as
`evidence_details.extra.resolved_action_digest`. The lookup is off unless
`WORKFLOW_ACTION_DIGEST_LOOKUP` is set, because a scanner that quietly makes an outbound request
per finding is one nobody can reason about and the Action's contract is that nothing leaves the
runner. Every failure -- unreachable API, rate limit, deleted tag -- produces no digest rather than
a guess, and the repair service refuses that case by name.

### Rule ids are resolved, not taken as given

Pointed at a directory, the scanner names a rule after the path it loaded it from relative to
the working directory, so the same rule arrives as `opengrep_rules.<id>` from one caller and
`services.analysis-service.src.opengrep_rules.<id>` from another. `canonical_check_id` resolves
the id back to the one the rule file declares. Without it a rule id could not key the posting
policy, a suppression, or a fingerprint.
