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
    "set-cookie-outside-helper": ("x.rs",
        'resp.append_header((header::SET_COOKIE, format!("sid={v}")));',
        'SetCookie::new(SESSION_COOKIE, &v, 60, SameSite::Strict).apply(&mut resp);'),
    "notes-owner-scope": ("x.rs",
        'sqlx::query("DELETE FROM notes WHERE id = $1").bind(id)',
        'sqlx::query("DELETE FROM notes WHERE id = $1 AND owner_id = $2").bind(id).bind(uid)'),
    "notes-owner-scope-mail": ("x.rs",
        'sqlx::query("SELECT body_enc FROM mail_messages WHERE id = $1").bind(id)',
        'sqlx::query("SELECT body_enc FROM mail_messages WHERE id = $1 AND owner_id = $2")'),
    "notes-owner-scope-labels": ("x.rs",
        'sqlx::query("DELETE FROM mail_labels WHERE account_id = $1").bind(id)',
        'sqlx::query("DELETE FROM mail_labels WHERE owner_id = $1 AND account_id = $2")'),
    "notes-owner-scope-totals": ("x.rs",
        'sqlx::query("SELECT total FROM mail_gmail_totals WHERE account_id = $1").bind(id)',
        'sqlx::query("SELECT total FROM mail_gmail_totals WHERE owner_id = $1 AND account_id = $2")'),
    "notes-owner-scope-multiline": ("x.rs",
        'sqlx::query_as::<_, Note>(\n    "SELECT id, title\n     FROM notes ORDER BY created_at",\n)',
        'sqlx::query_as::<_, Note>(\n    "SELECT id, title FROM notes\n     WHERE owner_id = $1",\n)'),
    "outbound-http": ("x.rs",
        "let c = reqwest::Client::new(); c.get(user_url).send().await?;",
        "let u: reqwest::Url = cfg.redirect_uri.clone();"),
    "directory-listing-template": ("default.conf.template", "autoindex on;", "autoindex off;"),
    "cookie-flags": ("x.rs",
        'let c = Cookie::build("sid", v).secure(true).finish();',
        'let c = Cookie::build("sid", v).secure(true).http_only(true).same_site(SameSite::Lax).finish();'),
}


ALIASES = {"sql-string-building-var": "sql-string-building", "sql-string-building-ident": "sql-string-building",
           "notes-owner-scope-multiline": "notes-owner-scope",
           "notes-owner-scope-mail": "notes-owner-scope",
           "notes-owner-scope-labels": "notes-owner-scope",
           "notes-owner-scope-totals": "notes-owner-scope",
           "directory-listing-template": "directory-listing"}


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

    def test_cfg_test_item_does_not_hide_rest_of_file(self):
        # A non-module `#[cfg(test)]` item must not blank everything after it.
        src = '#[cfg(test)]\nuse std::fs;\nfn prod() { std::fs::read("x"); }'
        self.assertIn("filesystem-access", rules_hit("x.rs", src))

    def test_code_after_test_module_is_still_scanned(self):
        src = ('#[cfg(test)]\nmod tests { fn t() { let s = "}"; let c = \'{\'; } }\n'
               'fn prod() { std::fs::read("x"); }')
        self.assertIn("filesystem-access", rules_hit("x.rs", src))

    def test_braces_in_literals_and_comments_do_not_end_module(self):
        src = ('#[cfg(test)]\nmod tests {\n    // }\n    /* } */\n'
               '    fn t() { let a = r#"}"#; let b = "\\"}"; std::fs::read("x"); }\n}\n')
        self.assertNotIn("filesystem-access", rules_hit("x.rs", src))

    def test_unterminated_test_module_is_scanned(self):
        src = '#[cfg(test)]\nmod tests {\n fn t() { std::fs::read("x"); }\n'
        self.assertIn("filesystem-access", rules_hit("x.rs", src))

    def test_stripping_preserves_line_numbers(self):
        src = 'fn a() {}\n#[cfg(test)]\nmod tests {\n  fn t() {}\n}\nfn b() {}\n'
        out = cc.strip_rust_tests(src)
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertEqual(out.splitlines()[5], "fn b() {}")

    def test_confined_rules_allow_only_their_module(self):
        # outbound-http / set-cookie-outside-helper exempt exactly one file each.
        http = "let c = reqwest::Client::builder().build()?;"
        cookie = "resp.append_header((header::SET_COOKIE, v));"
        self.assertEqual(rules_hit("backend/src/auth/google.rs", http), set())
        self.assertIn("outbound-http", rules_hit("backend/src/routes/notes.rs", http))
        self.assertEqual(rules_hit("backend/src/auth/cookies.rs", cookie), set())
        self.assertIn("set-cookie-outside-helper", rules_hit("backend/src/auth/mod.rs", cookie))

    def test_test_fn_pattern_matches_only_marked_tests(self):
        # Only functions under a test attribute count as `test:` evidence.
        src = (
            "fn helper() {}\n"
            "pub async fn handler() {}\n"
            "#[test]\nfn plain() {}\n"
            "#[actix_web::test]\nasync fn web() {}\n"
            "#[tokio::test(flavor = \"multi_thread\")]\nasync fn tokio_flavored() {}\n"
            "#[test]\n#[ignore]\n/// doc\n// note\nfn with_attrs() {}\n"
            "#[cfg(test)]\nfn cfg_only() {}\n"
        )
        self.assertEqual(set(cc.TEST_FN.findall(src)),
                         {"plain", "web", "tokio_flavored", "with_attrs"})

    def test_spec_ids_complete(self):
        self.assertEqual(len(cc.SPEC_IDS), 55)
        self.assertEqual(len(set(cc.SPEC_IDS)), 55)


if __name__ == "__main__":
    unittest.main()
