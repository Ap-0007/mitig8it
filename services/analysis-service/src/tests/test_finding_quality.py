from finding_quality import (
    cluster_findings,
    extract_match_context,
    is_transcript_artifact_line,
    pattern_matches_reviewable_content,
)
from security_rules import SECURITY_RULES


def _find(rule_id):
    return next(rule for rule in SECURITY_RULES if rule.rule_id == rule_id)


class TestTranscriptFiltering:
    def test_flags_transcript_artifact_line(self):
        assert is_transcript_artifact_line('    218 +        patch = "+API_KEY = \'sk_live_1234567890abcdef\'"')

    def test_keeps_real_code_line(self):
        assert not is_transcript_artifact_line('api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"')

    def test_ignores_secret_match_in_transcript_text(self):
        rule = _find("secret.hardcoded.credential")
        patch = '+    218 +        patch = "+API_KEY = \'sk_live_1234567890abcdef\'"'
        assert not pattern_matches_reviewable_content(patch, rule.pattern)

    def test_keeps_real_secret_match(self):
        rule = _find("secret.hardcoded.credential")
        patch = '+api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"'
        assert pattern_matches_reviewable_content(patch, rule.pattern)

    def test_extract_match_context_prefers_real_code_over_transcript(self):
        rule = _find("code.injection.eval")
        patch = "\n".join(
            [
                "@@ -1,2 +1,3 @@",
                '+    68 -            "patch": "+const result = eval(req.body.code)",',
                "+const result = eval(user_input)",
            ]
        )
        context = extract_match_context(patch, rule.pattern)
        assert context["matched_text"] == "const result = eval(user_input)"


def test_source_comments_and_literals_cannot_hide_runtime_eval():
    rule = _find("code.injection.eval")
    for suffix in (" # git add .", " # pytest", ' # "diff_hunk"', " # OpenGrep validation failed"):
        assert pattern_matches_reviewable_content("+eval(user_input)" + suffix, rule.pattern)


# Tier 1 and tier 2 both detect one raw SQL query on one line. Before the taxonomy was
# made tier-independent they carried different internal types (`sql_injection` against
# the opengrep check id), never clustered, and the pull request received two inline
# comments and two GitHub suggestions on the same line.
class TestCrossTierClustering:
    FILE = "services/orders.js"
    LINE = "  const rows = await db.query(`SELECT * FROM orders WHERE id = ` + id);"

    def _tier1(self):
        from main import generate_finding

        patch = "@@ -1,2 +1,3 @@\n+const db = require('./db');\n+" + self.LINE
        return generate_finding(_find("sql.injection.raw_query"), self.FILE, patch)

    def _tier2(self):
        from opengrep_runner import _build_finding

        match = {
            "check_id": "cwe-89.sql-template-literal",
            "path": "scan-root/" + self.FILE,
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "SQL query built from a template literal",
                "severity": "ERROR",
                "lines": self.LINE,
                "metadata": {"cwe": "CWE-89", "owasp": "A03:2021", "category": "SQL injection", "confidence": "0.9"},
            },
        }
        content = "const db = require('./db');\n" + self.LINE + "\n"
        return _build_finding(match, "scan-root", {self.FILE: content})

    def test_both_tiers_name_the_same_internal_type(self):
        assert self._tier1()["internal_type"] == "sql_injection"
        assert self._tier2()["internal_type"] == "sql_injection"

    def test_the_two_tiers_cluster_into_one_finding_that_keeps_both_rule_ids(self):
        tier1 = self._tier1()
        tier2 = self._tier2()
        assert tier1["fingerprint"] != tier2["fingerprint"]

        clustered = cluster_findings([tier1, tier2])

        assert len(clustered) == 1
        survivor = clustered[0]
        assert survivor["merged_rule_ids"] == [tier2["rule_id"], tier1["rule_id"]]
        assert survivor["evidence_details"]["extra"]["merged_rule_ids"] == survivor["merged_rule_ids"]
        # The survivor keeps the higher-confidence evidence and the union of the taxonomy.
        assert survivor["confidence"] >= max(tier1["confidence"], tier2["confidence"])
        assert survivor["cwe_id"] == "CWE-89"
        assert tier1["rule_id"] in survivor["evidence"]

    def test_a_single_finding_is_left_untouched(self):
        clustered = cluster_findings([self._tier1()])

        assert len(clustered) == 1
        assert "merged_rule_ids" not in clustered[0]


# One `md5(password.encode())` produced two comments on the same line for the whole
# September 2026 action trial: a critical "Password hashed with weak algorithm" from tier 2
# and a medium "Weak cryptographic hash used for security context" from tier 1, on
# `introduction/mitre.py:161` and `introduction/views.py:1026`. The clusterer merges only
# within one internal type and the two rules disagreed about the name: CWE-916
# (`weak_password_hash`) against CWE-327 (`weak_cipher_algorithm`). They agree now.
class TestWeakPasswordHashClustering:
    FILE = "introduction/mitre.py"
    LINE = "    hashed = hashlib.md5(password.encode()).hexdigest()"

    def _tier1(self, line=None):
        from main import generate_finding

        patch = "@@ -1,2 +1,3 @@\n+def login(request):\n+" + (line or self.LINE)
        return generate_finding(_find("crypto.weak.hash"), self.FILE, patch)

    def _tier2(self):
        from opengrep_runner import _build_finding

        match = {
            "check_id": "cwe-327.weak-hash-password",
            "path": "scan-root/" + self.FILE,
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {
                "message": "Password hashed with weak algorithm - use bcrypt or argon2",
                "severity": "ERROR",
                "lines": self.LINE,
                "metadata": {
                    "cwe": "CWE-916", "owasp": "A02:2021",
                    "category": "weak password hashing", "confidence": "0.88",
                },
            },
        }
        content = "def login(request):\n" + self.LINE + "\n"
        return _build_finding(match, "scan-root", {self.FILE: content})

    def test_both_tiers_name_the_same_internal_type(self):
        assert self._tier1()["internal_type"] == "weak_password_hash"
        assert self._tier2()["internal_type"] == "weak_password_hash"

    def test_the_two_rules_cluster_into_one_comment(self):
        tier1 = self._tier1()
        tier2 = self._tier2()

        clustered = cluster_findings([tier1, tier2])

        assert len(clustered) == 1
        survivor = clustered[0]
        assert set(survivor["merged_rule_ids"]) == {tier1["rule_id"], tier2["rule_id"]}
        # The worse of the two is what a reader is left with.
        assert survivor["severity"] == "critical"

    def test_a_weak_hash_of_something_that_is_not_a_credential_keeps_its_own_type(self):
        """dvna's `md5(req.query.login)` reset token is a weak cipher, not a password hash."""
        finding = self._tier1("    const token = md5(req.query.login).digest();")
        assert finding["internal_type"] == "weak_cipher_algorithm"


# The two workflow rules that can both fire on one `actions/checkout` step. Unlike the classes
# above, this is not two detectors agreeing on one flaw: the rules describe different flaws, one of
# which exists only because of the other. `cluster_findings` will not merge them, because they
# carry different internal types, so the reconciliation is the directional fold in
# `_apply_subsumption` and the table it reads, `SUBSUMED_INTERNAL_TYPES`.
#
# The integrated path, over real scanner output on real workflow files, is
# `benchmarks/tier2-precision/cases.json`. What is here is the edges of the rule the table states:
# the direction, the distance, and what the fold is not allowed to change.
class TestCredentialPersistenceFoldsIntoUntrustedCheckout:
    FILE = ".github/workflows/fixup.yml"

    def _checkout(self, line=10):
        return {
            "rule_id": "opengrep.cwe-829.gha-untrusted-checkout-privileged-trigger",
            "internal_type": "untrusted_code_checkout",
            "file_path": self.FILE,
            "line_start": line,
            "line_end": line,
            "severity": "critical",
            "confidence": 0.9,
            "code_snippet": "          ref: ${{ github.event.pull_request.head.ref }}",
            "description": "This workflow checks out the pull request's own revision.",
            "taxonomy_mappings": {"cwe": ["CWE-829"], "owasp": ["A08:2021"]},
        }

    def _persist(self, line=11, path=None):
        return {
            "rule_id": "opengrep.cwe-522.gha-persist-credentials-on-untrusted-checkout",
            "internal_type": "workflow_credential_persistence",
            "file_path": path or self.FILE,
            "line_start": line,
            "line_end": line,
            "severity": "high",
            "confidence": 0.85,
            "code_snippet": "          persist-credentials: true",
            "description": "This checkout keeps the job's token in `.git/config`.",
            "taxonomy_mappings": {"cwe": ["CWE-522"], "owasp": ["A07:2021"]},
        }

    def test_one_finding_survives_and_it_is_the_checkout(self):
        """The survivor is pinned by the table, not chosen by severity or confidence."""
        clustered = cluster_findings([self._persist(), self._checkout()])

        assert len(clustered) == 1
        assert clustered[0]["rule_id"] == self._checkout()["rule_id"]

    def test_the_survivor_still_records_that_both_rules_matched(self):
        clustered = cluster_findings([self._checkout(), self._persist()])
        survivor = clustered[0]

        assert survivor["merged_rule_ids"] == [self._checkout()["rule_id"], self._persist()["rule_id"]]
        # The extras map is the one place on a finding that crosses the gRPC contract intact.
        assert survivor["evidence_details"]["extra"]["merged_rule_ids"] == survivor["merged_rule_ids"]
        assert self._persist()["rule_id"] in survivor["evidence"]

    def test_folding_does_not_raise_confidence(self):
        """Two detectors agreeing is evidence. A consequence agreeing with its cause is not."""
        clustered = cluster_findings([self._checkout(), self._persist()])

        assert clustered[0]["confidence"] == self._checkout()["confidence"]

    def test_persist_credentials_alone_still_gets_its_own_finding(self):
        """An ordinary `pull_request` workflow: nothing subsumes it, so the one line is the fix."""
        clustered = cluster_findings([self._persist()])

        assert len(clustered) == 1
        assert clustered[0]["rule_id"] == self._persist()["rule_id"]
        assert "merged_rule_ids" not in clustered[0]

    def test_the_fold_is_one_directional(self):
        """The checkout finding is never dropped in favour of the credential one.

        Stop persisting the credential and the untrusted checkout is still there, so the reverse
        of this table entry is not true and must not be inferred from it.
        """
        clustered = cluster_findings([self._persist(), self._checkout()])

        assert {finding["rule_id"] for finding in clustered} == {self._checkout()["rule_id"]}

    def test_a_credential_finding_in_another_file_is_left_alone(self):
        clustered = cluster_findings(
            [self._checkout(), self._persist(path=".github/workflows/release.yml")]
        )

        assert len(clustered) == 2
        assert all("merged_rule_ids" not in finding for finding in clustered)

    def test_a_credential_finding_in_a_different_step_is_left_alone(self):
        """Far enough away to be another checkout step, which is another finding."""
        clustered = cluster_findings([self._checkout(line=10), self._persist(line=40)])

        assert len(clustered) == 2
        assert all("merged_rule_ids" not in finding for finding in clustered)

    def test_an_unrelated_pair_of_findings_is_untouched(self):
        """The table is consulted, and nothing else changes shape because it exists."""
        other = {**self._persist(), "internal_type": "workflow_secret_exposure",
                 "rule_id": "opengrep.cwe-200.gha-secret-in-untrusted-checkout-job"}
        clustered = cluster_findings([self._checkout(), other])

        assert len(clustered) == 2
