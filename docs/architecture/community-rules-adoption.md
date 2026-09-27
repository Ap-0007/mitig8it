# What tier 2 should detect next

Status: plan. Replaces the 2026-09-25 draft, which assumed the Semgrep or
OpenGrep registry could be vendored.

## Two corrections to the draft

**The registry cannot be used.** Registry rules are under the Semgrep Rules
License, which forbids making them available as a service. The OpenGrep fork's
licence is LGPL 2.1 plus the Commons Clause, which forbids selling a product
whose value derives from them. Both were read in full and recorded in
[third-party-rules.md](../legal/third-party-rules.md). Every rule this product
ships is written in this repository for that reason.

**The rule count is not 63.** Tier 2 carries 130 in-house rules, of which 124
post and 6 are quarantined on their own measured precision. Tier 1 carries
about 30 regex rules, of which 6 are quarantined. Precision of what posts is
0.97 over 172 hand-adjudicated findings on 23 vulnerable repositories; recall on
labelled vulnerabilities is 0.58. The numbers and the method are in
[docs/validation](../validation/README.md).

So the work is not replacing the rules. It is the categories nobody has written
yet, and the verification level those categories need.

## What a maintainer is exposed to

Coverage is chosen by what an open source maintainer needs when a stranger opens
a pull request. The first threat is a contributor attacking the repository. Only
after that is it a contributor writing careless code.

| # | Category | State |
| --- | --- | --- |
| 1 | Workflow tampering | missing |
| 2 | Secrets in the diff | partial: one tier 1 credential rule, no entropy or key formats |
| 3 | Obfuscated or dynamic code | missing |
| 4 | Dependency additions | missing, and it is composition analysis rather than a rule |
| 5 | SQL parameterization | 8 rules, repair family |
| 6 | Command arguments | 6 rules, repair family |
| 7 | Path containment | 6 rules, repair family |
| 8 | Hardcoded credentials | 7 rules, repair family |
| 9 | Code injection and eval | 6 rules, repair family |
| 10 | XSS | 7 rules plus 9 template rules, recall 26 of 32 |
| 11 | Deserialization | 5 rules, recall 11 of 11 |
| 12 | SSRF | 4 rules |
| 13 | XXE | 1 rule, thin |
| 14 | Framework misconfiguration | 11 rules |

Categories 5 to 14 exist. Categories 1 to 4 are the work, and they rank above
everything else because they are what a stranger's pull request can do to a
maintainer.

## The obstacle is proof, not patching

Several of the new findings are deterministically fixable: pin an action to a
commit digest, remove an untrusted checkout under `pull_request_target`, quote a
shell interpolation in a `run` block, move a literal secret to the environment.

The current verification contract is a regression test that must fail on the
original code and pass on the patch. No unit test can demonstrate that a
workflow is secure or that a secret is gone, and the pairs measurement showed
the sandbox cannot even load most real modules: 84 findings are refused because
a dependency is missing, and all 8 fixes that verify are modules with no imports
beyond the standard library.

So these categories need a second verification level, a static assertion: the
rule that produced the finding fires on the original file, does not fire on the
patched file, and nothing else in the file changed. It executes nothing. It is
weaker than the sandbox proof and must carry its own name so the evidence shown
to a reviewer never overstates what was checked.

That level is also the cheapest route to moving verified fixes off 8.

## Order

1. The static assertion verification level.
2. Workflow tampering rules, with fixes proven on that level.
3. Secrets in the diff: entropy and key formats, fix is a move to the
   environment, proven on that level.
4. Obfuscated and dynamic code.
5. Dependency additions, judged by tier 3, which is the one question a pattern
   cannot express. In the Action this needs registry lookups, so it is opt-in
   there and off by default, because the Action's contract is that nothing
   leaves the runner.
6. XXE to full coverage, and port the surviving tier 1 rules to the same YAML
   engine so there is one rule format and one dedup path.

## What does not change

Every new rule obeys the posting policy: a rule posts only on measured precision
of at least 0.8 over at least three adjudicated findings, or as a sink-only
pattern with a clear taxonomy that produced nothing on the clean corpus. A rule
that fails that test still runs and is still counted, and nothing it produces
reaches a reviewer.

Tier 1 is not deleted wholesale. Its measured precision is 0.96 once the six
quarantined rules are excluded, and its credential rule scans prose, which tier
2 does not. A rule is removed when the benchmark says the replacement covers it.
