# What a static assertion reaches, September 2026

[pairs-2026-09.md](pairs-2026-09.md) ended by naming one number as the binding constraint. Of 249
supported-family findings on the 23-repository vulnerable corpus, the template writes a patch for
62 and the service writes a proof for 16; 8 findings have both halves, all 8 verify, and all 8 are
hardcoded credentials. The largest single reason a finding gets no proof is that the module the
proof would load imports a package a dependency-free sandbox has no copy of.

The 54 findings with a patch and no proof were the whole cost of insisting on execution. Each one
had a deterministic repair written and nothing to say about it, so nothing shipped.

This is the measurement of the level that was added for exactly those: `static_assertion`, where
nothing is executed and the rule that produced the finding is re-run over the original and the
patched file instead. It is the weakest level the product has and it is weaker in kind rather than
in degree. The five clauses are in
[../../services/remediation-service/contracts/repair-v1.md](../../services/remediation-service/contracts/repair-v1.md);
what an assertion is worth, next to an executed proof, is in
[../design/prove-before-post.md](../design/prove-before-post.md).

## How it was measured

The same instrument as the page above, extended in one place. `scripts/replay/replay.py --pairs`
reads the findings out of 23 snapshot runs and joins them back to the same pinned trees. For each
finding it calls the engine's own pieces: `static_gate` decides whether the finding is attempted,
`generate_proof` and `generate_template` decide the two halves, a finding with both gets a real
`build_patch_bundle` and a real `Verifier` run over the local sandbox, and **a finding with a patch
and no proof now gets a real `verify_static_assertion` over the real rule set of both tiers**.
Nothing is re-implemented. The route into the assertion is the engine's own
`static_assertion_reason`, so a finding measured here is asserted for the reason the engine would
have recorded, or not attempted at all.

A finding with a proof that fails is not asserted instead. Execution was available to it and it did
not hold, and reaching for a weaker level after a stronger one has answered is the one thing this
level must never do.

The counts are two columns and not one. **`verified` is the executed count**: a proof that failed on
the original tree and passed on the patched one. **`asserted` is the static assertion count.** They
are different claims about different findings, and adding them without saying which is which would
be the dishonesty the level's name exists to prevent.

The 23 snapshot runs were taken on this branch, at the same pinned refs as the corpus labels, and
they reproduce the 249 of the page above exactly. Nothing on this branch changes detection.

## Before and after

| | Before | After |
| --- | ---: | ---: |
| Supported-family findings whose file the snapshot carries | 249 | 249 |
| Findings the template builds a patch for | 62 | 62 |
| Findings the service writes a proof for | 16 | 16 |
| Findings with both halves | 8 | 8 |
| Pairs that verify end to end, by execution | 8 | 8 |
| Findings with a patch and no proof, where the assertion is the only route | 54 | 54 |
| Those the static assertion carries | — | **9** |
| **A verified fix at any level** | **8** | **17** |

Nine findings out of 54, and the honest way to read that is in two halves, because the 54 are not
one population.

| | Findings | Assertion tried | Asserted |
| --- | ---: | ---: | ---: |
| From rules that post | 163 | 13 | **9** |
| From rules quarantined on their own measured precision | 86 | 41 | 0 |
| Total | 249 | 54 | 9 |

**Every one of the 41 quarantined-rule findings was refused, and all 41 are the same rule.**
`path.traversal.user_path` is quarantined at a measured precision of 0.43, so nothing it produces is
posted or sent to remediation in the first place; it appears here only because the snapshot runs
were taken with `--include-quarantined` so quarantined rules stay measurable. Each of the 41 is
refused on clause 2: the rule is a regular expression that pairs a file-access call with any of
`../`, `req.`, `input(`, `+`, `f"` or `{` anywhere after it, and a containment repair still has the
call and still has one of those. In `pygoat/introduction/views.py` the surviving match is
`open(filename, "w+")`, matched on the `+` of the mode string, on a line the repair did not change
the meaning of. The assertion is correct to refuse anyway. A rule that still fires on the patched
file is a rule that says the finding is still there, and a level whose whole claim is "the rule no
longer matches" cannot overrule it: the alternative would be for the assertion to decide which of a
rule's matches it is entitled to ignore, which is the detector's judgement and not the verifier's.
The quarantine evidence on that rule records the same brace alternative as the source of every false
positive it was quarantined for.

On the half that can actually be posted, the number is 9 of 13, and **the product goes from 8
verified fixes on real vulnerable code to 17.**

## The nine

| Repository | Path | Rule | Why execution was not available |
| --- | --- | --- | --- |
| `appsecco/dvna` | `server.js:24` | `opengrep.cwe-798.js-session-secret-literal` | `dependency_not_available_in_sandbox:body-parser` |
| `electerm/electerm` | `src/client/common/constants.js:208` | `opengrep.cwe-798.js-credential-constant` | `dependency_not_available_in_sandbox:@electerm` |
| `snyk-labs/nodejs-goof` | `app.js:43` | `opengrep.cwe-798.js-session-secret-literal` | `dependency_not_available_in_sandbox:st` |
| `juice-shop/juice-shop` | `routes/fileServer.ts:32` | `opengrep.cwe-22.js-sendfile-request-path` | `dependency_not_available_in_sandbox:@juice-shop` |
| `juice-shop/juice-shop` | `routes/keyServer.ts:14` | `opengrep.cwe-22.js-sendfile-request-path` | `no_untrusted_parameter` |
| `juice-shop/juice-shop` | `routes/logfileServer.ts:14` | `opengrep.cwe-22.js-sendfile-request-path` | `no_untrusted_parameter` |
| `juice-shop/juice-shop` | `routes/quarantineServer.ts:14` | `opengrep.cwe-22.js-sendfile-request-path` | `no_untrusted_parameter` |
| `juice-shop/juice-shop` | `routes/vulnCodeFixes.ts:81` | `opengrep.cwe-22.path-traversal-fs` | `dependency_not_available_in_sandbox:js-yaml` |
| `juice-shop/juice-shop` | `routes/vulnCodeSnippet.ts:90` | `opengrep.cwe-22.path-traversal-fs` | `dependency_not_available_in_sandbox:js-yaml` |

Three `hardcoded_credential` and six `path_containment`, all tier 2 rules, all of which post.

One thing in that table is worth more than the count. **The 8 that verify by execution are all
`hardcoded_credential`.** Six of the nine here are `path_containment`, which is a family that had
never reached a verified fix on real vulnerable code at any level. The reason is the same reason
the family is hard to prove: a path traversal repair lives in a request handler, the handler lives
in a module that imports the application's framework, and the sandbox has none of it. The rule
re-run needs no framework.

The three credentials are the shape the corpus is full of: a literal at module scope in a file whose
import closure the sandbox cannot supply. That is the pair `pairs-2026-09.md` counts 84 of.

## The four that were refused, and why the clause is right

| Repository | Path | Rule | Refusal |
| --- | --- | --- | --- |
| `juice-shop/juice-shop` | `frontend/src/app/register/register.component.spec.ts:137` | `opengrep.cwe-798.hardcoded-secret-js` | `static_assertion_rule_still_matches_patch` |
| `juice-shop/juice-shop` | `frontend/src/app/register/register.component.spec.ts:138` | `opengrep.cwe-798.hardcoded-secret-js` | `static_assertion_rule_still_matches_patch` |
| `scitokens/scitokens` | `src/scitokens/utils/keycache.py:83` | `sql.injection.raw_query` | `static_assertion_rule_still_matches_patch` |
| `scitokens/scitokens` | `src/scitokens/utils/keycache.py:83` | `opengrep.cwe-89.py-execute-concat-direct` | `static_assertion_rule_still_matches_patch` |

All four are one situation: the repair fixed the finding's own line and the file has other lines the
same rule matches. `register.component.spec.ts` carries a third password literal on line 117 that no
finding named, so repairing lines 137 and 138 leaves the rule matching. `keycache.py` builds several
more statements the same way: the tier 1 rule still matches two of them and the tier 2 rule four.

Clause 2 is whole-file on purpose. An assertion has no finding identity to work with: it has a rule,
a path, and two file texts, and "the rule matches the patched file at line 140" is indistinguishable
from "the repair did not work" without re-running the detector's own deduplication and clustering.
Narrowing the clause to the finding's own line would make it possible to assert that a file is fixed
while the same defect sits four lines down, which is precisely the failure
[../design/prove-before-post.md](../design/prove-before-post.md) is about. Refusing all four is
conservative and it is the right side to be conservative on.

It does name a reachable improvement, and it is not a change to the clause: a job that repairs every
site of one rule in one file would assert the file, because the rule would then match nothing. That
is a grouping question rather than a verification question.

**Every refusal on this corpus was clause 2.** No finding was refused for reaching another file
(clause 3, first part), for changing a line outside the finding's region and the template's declared
hunks (clause 3, second part), or for starting a new rule matching (clause 4). That is worth stating
because it is a measurement of the templates rather than of the level: the deterministic repairs
change what they say they change, and they do not trade one rule's finding for another's.

## What this does not say

**It is not nine fixes proven to work.** Nothing ran. For each of the nine, no test demonstrated the
vulnerability was reachable before the change, nothing demonstrated the feature still works after
it, the repository's own suite did not run, and the patched module was never even loaded. A reviewer
reading one of these sees all of that in the evidence, because the level's own limitations say it.

**It is not evidence that the nine findings were real.** An assertion is a claim about what a rule
thinks of two file texts. If a rule fires on safe code, a patch that stops it firing asserts nothing
worth having, which is why the precision of the rules themselves
([vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md)) is the number that decides whether
these nine are worth anything, not this page.

**It does not move the executed count at all.** That stays at 8, and the constraint behind it is
unchanged: a dependency-free sandbox can only load a dependency-free module. The assertion does not
solve that problem. It reports honestly on the findings the problem leaves behind, which is a
different and smaller thing.

**Nine of 249 is not a rate.** It is nine findings in nine files of five repositories, counted once.

## Reproducing this

```sh
PY=~/.pyenv/versions/3.11.6/bin/python

# once per repository, from benchmarks/vulnerable-corpus/labels.json
$PY scripts/replay/replay.py --snapshot --include-quarantined \
    --repo OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 \
    --out scripts/replay/results/nodegoat.json

# the pairs and the assertions, with a clean interpreter first on PATH so the sandbox has no
# host packages
PATH=/path/to/empty-venv/bin:$PATH \
  $PY scripts/replay/replay.py --pairs --results scripts/replay/results/*.json --out /tmp/pairs.json
$PY scripts/replay/summarize.py --pairs /tmp/pairs.json
```

The before column is the same run with the `asserted` column read as zero: the executed path is
untouched by this work, and the measurement confirms it, reproducing 62 patches, 16 proofs, 8 pairs
and 8 verified exactly. `summarize.py --pairs` prints the per-finding assertion table and the
refusal counts under **The static assertion, per finding**.

The authored corpus measures the same level from the other direction. Five of the 63 fixtures in
[../../benchmarks/remediation/README.md](../../benchmarks/remediation/README.md) declare
`expected_verification_level: static_assertion` and are held to exactly that level in both
directions, so a fixture that quietly stopped being executed fails rather than reading as a pass.
