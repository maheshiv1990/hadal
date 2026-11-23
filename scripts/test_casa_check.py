"""Self-tests for the CASA gate: every rule must fire on a known-bad sample and stay
quiet on the safe equivalent. Run: python3 -m unittest scripts/test_casa_check.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import casa_check as cc  # noqa: E402

# rule id -> (file name, bad snippet, good snippet)
CASES = {
    "sql-string-building": ("x.rs",
        'sqlx::query(&format!("SELECT * FROM notes WHERE id = {id}"))',
        'sqlx::query("SELECT * FROM notes WHERE id = $1").bind(id)'),
    "sql-string-building-var": ("x.rs",
        'let sql = "SELECT * FROM notes WHERE t LIKE \'%".to_owned() + &q;',
        'let n = sqlx::query_as::<_, Note>("SELECT 1").fetch_all(p).await?;'),
    "sql-string-building-ident": ("x.rs",
        "let notes = sqlx::query_as::<_, Note>(&sql).fetch_all(p).await?;",
        'let notes = sqlx::query_as::<_, Note>("SELECT id FROM notes").fetch_all(p).await?;'),
    "os-command": ("x.rs", 'std::process::Command::new("sh")', "let cmd = 1;"),
    "filesystem-access": ("x.rs", "let f = std::fs::read_to_string(p);", "let f = 1;"),
    "directory-listing": ("a.conf", "autoindex on;", "autoindex off;"),
    "origin-header-auth": ("x.rs", 'req.headers().get("origin")', 'req.headers().get("x-real-ip")'),
    "sensitive-logging": ("x.rs",
        'tracing::info!(\n  user = %u,\n  password = %pw,\n  "login");',
        'tracing::info!(user = %u, "login");'),
    "sensitive-logging-js": ("a.ts", "console.log('token', t)", "console.log('loaded')"),
    "weak-crypto": ("x.rs", "let h = md5::compute(b);", "let h = sha2::Sha256::digest(b);"),
    "weak-crypto-deps": ("Cargo.toml", 'md-5 = "0.10"', 'sha2 = "0.10"'),
    "insecure-randomness": ("a.ts", "const id = Math.random()", "crypto.getRandomValues(buf)"),
    "dynamic-code": ("a.ts", "eval(userInput)", "JSON.parse(userInput)"),
    "raw-html-sink": ("a.tsx", "<div innerHTML={html} />", "<div>{text}</div>"),
    "tabnabbing": ("a.tsx", '<a href={u} target="_blank">', '<a href={u} target="_blank" rel="noopener noreferrer">'),
    "browser-storage": ("a.ts", "localStorage.setItem('t', tok)", "const s = new Map()"),
    "secret-in-url": ("a.ts", "fetch(`/api/x?access_token=${t}`)", "fetch('/api/x', { headers })"),
    "oauth-implicit-flow": ("a.ts", "params.set('response_type', 'token'); const q = 'response_type=token'", "response_type=code"),
    "open-redirect": ("a.ts", "window.location.href = next", "if (a === b) {}"),
    "insecure-transport": ("a.ts", "fetch('http://api.example.com')", "fetch('https://api.example.com')"),
    "tls-verification-disabled": ("x.rs", "builder.danger_accept_invalid_certs(true)", "builder.https_only(true)"),
    "default-accounts": ("m.sql", "INSERT INTO users (email) VALUES ('admin@x')", "INSERT INTO notes (id) VALUES ($1)"),
    "cors-wildcard": ("x.rs", "Cors::default().allow_any_origin()", 'Cors::default().allowed_origin("https://a.b")'),
    "hardcoded-secret": ("x.rs", 'let client_secret = "GOCSPX-abcdefgh123";', 'let client_secret = env::var("CLIENT_SECRET")?;'),  # gitleaks:allow (fake sample for the rule self-test)
    "debug-artifacts": ("x.rs", 'dbg!(x);', 'tracing::debug!(?x);'),
    "raw-query-string": ("x.rs", "let q = req.query_string();", "let q: web::Query<P> = q;"),
    "permissive-deserialize": ("x.rs",
        "#[derive(Deserialize)]\npub struct NewNote { title: String }",
        "#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct NewNote { title: String }"),
    "cookie-flags": ("x.rs",
        'let c = Cookie::build("sid", v).secure(true).finish();',
        'let c = Cookie::build("sid", v).secure(true).http_only(true).same_site(SameSite::Lax).finish();'),
}


ALIASES = {"sql-string-building-var": "sql-string-building", "sql-string-building-ident": "sql-string-building"}


def rules_hit(name: str, text: str) -> set[str]:
    return {f.rule for f in cc.lint_file(name, text)}


class RuleSelfTest(unittest.TestCase):
    def test_every_rule_has_a_case(self):
        untested = cc.RULE_IDS - {ALIASES.get(c, c) for c in CASES} - {"env-file-tracked"}
        self.assertFalse(untested, f"rules without self-tests: {untested}")

    def test_rules_fire_on_bad_and_pass_good(self):
        for rule, (name, bad, good) in CASES.items():
            rule = ALIASES.get(rule, rule)
            with self.subTest(rule=rule, bad=bad):
                self.assertIn(rule, rules_hit(name, bad), f"{rule} missed: {bad}")
                self.assertNotIn(rule, rules_hit(name, good), f"{rule} false positive: {good}")

    def test_suppression_requires_justification(self):
        bad = 'window.location.href = next'
        self.assertIn("open-redirect", rules_hit("a.ts", bad + " // casa-allow: open-redirect -- ok"))
        self.assertNotIn("open-redirect", rules_hit(
            "a.ts", bad + " // casa-allow: open-redirect -- constant OAuth endpoint URL"))

    def test_rust_test_modules_are_ignored(self):
        src = 'fn a() {}\n#[cfg(test)]\nmod tests { fn t() { std::fs::read("x"); } }'
        self.assertNotIn("filesystem-access", rules_hit("x.rs", src))

    def test_spec_ids_complete(self):
        self.assertEqual(len(cc.SPEC_IDS), 55)
        self.assertEqual(len(set(cc.SPEC_IDS)), 55)


if __name__ == "__main__":
    unittest.main()
