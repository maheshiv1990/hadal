#!/usr/bin/env python3
"""CASA gate for Hadal.

  casa_check.py lint [FILES...]   static CASA rules (all in-scope files by default)
  casa_check.py lint --hook       Claude Code PostToolUse hook: lint the edited file
  casa_check.py requirements      validate docs/casa/requirements.json against the
                                  CASA spec and the codebase (CASA_STRICT=1: pending fails)
  casa_check.py render            regenerate docs/casa/controls.md from the register
  casa_check.py list-rules        print every rule and the CASA items it enforces

Stdlib only. Exit 0 = pass, 1 = violations, 2 = hook violation (blocks Claude).
Suppress a single finding with a comment on the same or previous line:
    casa-allow: <rule-id> -- <justification of at least 15 chars>
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs/casa/requirements.json"
CONTROLS_MD = ROOT / "docs/casa/controls.md"

# Every audit item in ADA CASA Specification v2.1.1 (2026-06-03). The register
# must cover exactly this set, so nothing can be silently dropped.
SPEC_VERSION = "2.1.1"
SPEC_IDS = [
    "1.1.1", "1.1.2", "1.1.3", "1.2.1", "1.3.1", "1.3.2", "1.3.3", "1.3.4",
    "2.1.1", "2.2.1", "2.2.2", "2.2.3", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.4.1",
    "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.2.1", "3.2.2", "3.3.1",
    "4.1.1", "4.1.2", "4.1.3", "4.1.4",
    "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.1.5", "5.1.6", "5.1.7", "5.1.8", "5.1.9", "5.1.10",
    "5.2.1",
    "6.1.1", "6.2.1", "6.3.1", "6.4.1", "6.5.1", "6.6.1", "6.7.1",
    "7.1.1", "7.1.2", "7.2.1", "7.2.2", "7.2.3", "7.3.1", "7.3.2",
]
SECTIONS = {
    "1": "Authentication", "2": "Session Management", "3": "Access Control",
    "4": "Communications", "5": "Data Validation and Sanitization",
    "6": "Configuration", "7": "Webhook Security",
}
# Tools that scripts/verify.sh or CI actually run. Evidence may only cite these.
TOOLS = {
    "clippy", "cargo-test", "cargo-deny", "cargo-audit", "npm-audit",
    "gitleaks", "semgrep", "zap-baseline", "claude-review", "check-tls",
}

SCAN_GLOBS = [
    "backend/src/*.rs", "backend/src/**/*.rs", "backend/migrations/*.sql", "backend/Cargo.toml",
    "frontend/src/*", "frontend/src/**/*", "frontend/index.html", "frontend/vite.config.ts",
    "frontend/package.json", "nginx/*.conf", "nginx/*.conf.template", "docker-compose.yml", "docker-compose.prod.yml",
]
RS = ["*.rs"]
WEB = ["*.ts", "*.tsx", "*.js", "*.jsx", "*.html"]
CONF = ["*.conf", "*.conf.template"]
ALL = ["*"]


@dataclass
class Rule:
    id: str
    casa: list[str]
    files: list[str]
    pattern: str | None
    message: str
    multiline: bool = False
    custom: str | None = None
    exclude: list[str] = field(default_factory=list)


RULES: list[Rule] = [
    Rule("sql-string-building", ["5.1.8"], RS,
         r"\b(query|query_as|query_scalar|query_with|raw_sql)\s*(::<[^>]*>)?\s*\(\s*&?\s*(format!|concat!|[a-z_]\w*\s*[),+])"
         r"|(?i:format!\s*\(\s*\"[^\"]*\b(select|insert|update|delete|where)\b)"
         r"|(?i:\"[^\"]*\b(select|insert\s+into|update|delete\s+from|where)\b[^\"]*\"\s*(\.to_(owned|string)\(\))?\s*\+)",
         "SQL must be a static string with .bind() parameters; never build SQL with format!/concatenation."),
    Rule("os-command", ["5.1.9"], RS + WEB,
         r"\b(std::process::Command|tokio::process::Command|process::Command|Command::new|child_process)\b",
         "Spawning OS commands is forbidden in application code."),
    Rule("filesystem-access", ["5.1.10"], RS,
         r"\b(std::fs|tokio::fs|File::open|File::create|NamedFile|actix_files)\b",
         "Application code must not read/serve files from disk (file inclusion risk)."),
    Rule("directory-listing", ["3.1.6", "5.1.10"], RS + CONF,
         r"(show_files_listing|autoindex\s+on)", "Directory listing must stay disabled."),
    Rule("origin-header-auth", ["6.3.1"], RS,
         r"(?i)(header::ORIGIN|\"origin\")",
         "Do not read the Origin header; it must never drive authn/authz decisions."),
    Rule("sensitive-logging", ["6.5.1"], RS,
         r"\b(trace|debug|info|warn|error|event)!\s*\((?:(?!\);).)*?\b(?i:password|passwd|secret|token|api_?key|authorization|cookie|card_?number|cvv|database_url)\b",
         "Never log credentials, tokens, cookies or payment data (log a hash or omit).",
         multiline=True),
    Rule("sensitive-logging-js", ["6.5.1"], WEB,
         r"console\.\w+\([^)]*\b(?i:password|token|secret|authorization|cookie)\b",
         "Never log credentials or tokens from the frontend."),
    Rule("weak-crypto", ["4.1.3"], RS + WEB,
         r"\b(md5|md_5|sha1|sha_1|Md5|Sha1|des|rc4|Rc4|Ecb|ecb)::|createHash\(\s*['\"](md5|sha1)['\"]",
         "Weak hash/cipher; use SHA-256+, AES-GCM/ChaCha20-Poly1305, Argon2id."),
    Rule("weak-crypto-deps", ["4.1.3"], ["Cargo.toml", "package.json"],
         r"(?m)^\s*\"?(md5|md-5|sha1|sha-1|des|rc4|rust-crypto|crypto-js|md5-js)\"?\s*[=:]",
         "Weak crypto crate/package as a direct dependency."),
    Rule("insecure-randomness", ["4.1.3", "1.3.3"], RS + WEB,
         r"\b(SmallRng|seed_from_u64|Math\.random)\b",
         "Use a CSPRNG (rand::rngs::OsRng / crypto.getRandomValues) for anything security relevant."),
    Rule("dynamic-code", ["5.1.3"], WEB,
         r"\beval\s*\(|new\s+Function\s*\(|set(Timeout|Interval)\s*\(\s*['\"`]",
         "Dynamic code execution is forbidden."),
    Rule("raw-html-sink", ["5.1.7"], WEB,
         r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write(ln)?|dangerouslySetInnerHTML|createContextualFragment)\b",
         "Raw HTML sinks bypass Solid's escaping (DOM XSS)."),
    Rule("tabnabbing", ["5.1.7"], WEB, None,
         "target=\"_blank\" requires rel=\"noopener noreferrer\".", custom="tabnabbing"),
    Rule("browser-storage", ["6.6.1"], WEB,
         r"\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie",
         "Do not keep data or auth material in browser storage; use HttpOnly server sessions."),
    Rule("secret-in-url", ["2.1.1"], RS + WEB,
         r"(?i)[?&](access_token|id_token|refresh_token|token|password|passwd|api_?key|session(_?id)?|secret)=",
         "Credentials/tokens must never travel in URL query strings."),
    Rule("oauth-implicit-flow", ["3.2.1", "2.1.1"], RS + WEB,
         r"(?i)(response_type\s*[=:]\s*['\"]?(token|id_token)\b|grant_type\s*[=:]\s*['\"]?password\b)",
         "Only the Authorization Code flow with PKCE is allowed."),
    Rule("open-redirect", ["5.1.2"], RS + WEB,
         r"(header::LOCATION|\"[Ll]ocation\"|HttpResponse::(Found|SeeOther|TemporaryRedirect|PermanentRedirect|MovedPermanently)|web::Redirect|Redirect::to|\blocation\.(assign|replace)\s*\(|\blocation(\.href)?\s*=(?!=)|window\.open\s*\()",
         "Redirects must go to constant/allowlisted URLs; justify with casa-allow."),
    Rule("insecure-transport", ["4.1.1"], ALL,
         r"http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\]|www\.w3\.org/|backend\b|db\b)",
         "Plain http:// to a non-local host; use https://."),
    Rule("tls-verification-disabled", ["4.1.2"], ALL,
         r"(danger_accept_invalid_(certs|hostnames)|\.dangerous\(\)|sslmode=(disable|allow)\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|proxy_ssl_verify\s+off|ssl_protocols[^;]*TLSv1(\.1)?\b(?!\.))",
         "TLS verification must never be disabled; TLS < 1.2 is forbidden."),
    Rule("default-accounts", ["1.2.1"], ["*.sql"],
         r"(?i)insert\s+into\s+\S*(user|account|admin|member|login)s?\b",
         "Migrations must not seed accounts (default credentials)."),
    Rule("cors-wildcard", ["3.1.1", "3.1.5"], RS + CONF,
         r"(allow_any_origin|send_wildcard|Access-Control-Allow-Origin\"?\s+\"?\*)",
         "Wildcard CORS is forbidden; allowlist exact origins."),
    Rule("hardcoded-secret", ["6.7.1", "7.3.2", "1.2.1"], ALL,
         r"(?i)\b(secret|password|passwd|api_?key|client_secret|private_key|access_token)\s*[:=]\s*[\"'][^\"'\s$]{8,}[\"']|postgres(ql)?://[^:\s/@]+:(?![^@\s\"']*\$|change-me@)[^@\s\"']+@",
         "Hardcoded secret; load it from the environment / secrets manager."),
    Rule("debug-artifacts", ["6.2.1"], RS + WEB + ["vite.config.ts"],
         r"\b(dbg|println|eprintln)!|\bdebugger\b|RUST_BACKTRACE|sourcemap\s*:\s*true",
         "Debug output/source maps must not ship."),
    Rule("raw-query-string", ["5.1.1"], RS,
         r"\.query_string\(\)", "Parse query params via typed web::Query<T> (rejects duplicates), not by hand."),
    Rule("permissive-deserialize", ["3.1.2"], RS, None,
         "Request structs deriving Deserialize must use #[serde(deny_unknown_fields)] (mass assignment).",
         custom="permissive_deserialize"),
    Rule("cookie-flags", ["2.3.1", "2.3.2", "3.1.5"], RS, None,
         "Cookies must set .secure(true), .http_only(true) and .same_site(...).", custom="cookie_flags"),
    Rule("set-cookie-outside-helper", ["2.3.1", "2.3.2", "3.1.5"], RS,
         r"(?i)(\bSET_COOKIE\b|\"set-cookie\")",
         "Build cookies only with auth::cookies::SetCookie (fixed Secure/HttpOnly/SameSite).",
         exclude=["backend/src/auth/cookies.rs"]),
    Rule("notes-owner-scope", ["3.1.4", "3.1.1"], RS, None,
         "SQL touching user data (`notes`, `mail_accounts`, `mail_messages`) must be scoped by owner_id (IDOR).",
         custom="owner_scope"),
    Rule("outbound-http", ["5.1.5"], RS,
         r"\breqwest::(Client|ClientBuilder|get|blocking|Request|RequestBuilder)\b|\b(awc|ureq|isahc|surf|hyper_util)::",
         "Outbound HTTP is confined to auth/google.rs (fixed Google endpoint; SSRF).",
         exclude=["backend/src/auth/google.rs"]),
    Rule("env-file-tracked", ["6.7.1"], [], None,
         ".env files must never be committed.", custom="env_tracked"),
]
RULE_IDS = {r.id for r in RULES}

ALLOW_RE = re.compile(r"casa-allow:\s*([\w-]+)\s*--\s*(.{15,})")


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    text: str
    message: str
    casa: list[str]

    def __str__(self) -> str:
        return (f"{self.path}:{self.line}: [{self.rule}] (CASA {', '.join(self.casa)}) "
                f"{self.message}\n    {self.text.strip()[:160]}")


def git_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    return sorted({f for f in out if f})


def in_scope(rel: str) -> bool:
    return any(fnmatch.fnmatch(rel, g) for g in SCAN_GLOBS) and (ROOT / rel).is_file()


CFG_TEST_MOD_RE = re.compile(
    r"(?m)^[ \t]*#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{"
)
RUST_RAW_STR_RE = re.compile(r'b?r(#*)"')
RUST_CHAR_RE = re.compile(r"b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|.)|[^\\'\n])'")


def _rust_block_end(text: str, open_idx: int) -> int | None:
    """Index just past the `}` matching the `{` at `open_idx`, skipping braces inside
    comments, string/char literals and raw strings. None if it can't be matched."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if text.startswith("/*", i):
            nest, i = 1, i + 2
            while i < n and nest:
                if text.startswith("/*", i):
                    nest, i = nest + 1, i + 2
                elif text.startswith("*/", i):
                    nest, i = nest - 1, i + 2
                else:
                    i += 1
            if nest:
                return None
            continue
        prev_ident = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        raw = None if prev_ident else RUST_RAW_STR_RE.match(text, i)
        if raw:
            close = text.find('"' + raw.group(1), raw.end())
            if close == -1:
                return None
            i = close + 1 + len(raw.group(1))
            continue
        if c == '"' or (c == "b" and not prev_ident and text.startswith('b"', i)):
            i = text.index('"', i) + 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                return None
            i += 1
            continue
        if c in "'b" and not prev_ident:
            ch = RUST_CHAR_RE.match(text, i)
            if ch:
                i = ch.end()
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def strip_rust_tests(text: str) -> str:
    """Blank out `#[cfg(test)] mod name { ... }` blocks, keeping line numbers.

    Only whole test modules are removed, up to their matching brace. Any other
    `#[cfg(test)]` item, and anything after a test module, is still scanned. If a
    block's end can't be found, nothing more is stripped (fail towards scanning)."""
    out, pos = [], 0
    while (m := CFG_TEST_MOD_RE.search(text, pos)) is not None:
        end = _rust_block_end(text, m.end() - 1)
        if end is None:
            break
        out.append(text[pos:m.start()])
        out.append("\n" * text.count("\n", m.start(), end))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def read(rel: str) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    return strip_rust_tests(text) if rel.endswith(".rs") else text


def matches_files(rule: Rule, rel: str) -> bool:
    name = os.path.basename(rel)
    if any(fnmatch.fnmatch(rel, g) for g in rule.exclude):
        return False
    return any(fnmatch.fnmatch(name, g) for g in rule.files)


def suppressed(lines: list[str], idx: int, rule_id: str) -> bool:
    for j in (idx, idx - 1):
        if 0 <= j < len(lines):
            m = ALLOW_RE.search(lines[j])
            if m and m.group(1) == rule_id:
                return True
    return False


def lint_file(rel: str, text: str | None = None) -> list[Finding]:
    if text is None:
        text = read(rel)
    elif rel.endswith(".rs"):
        text = strip_rust_tests(text)
    lines = text.split("\n")
    found: list[Finding] = []

    def add(rule: Rule, offset_or_line: int, is_line: bool = False) -> None:
        line_no = offset_or_line if is_line else text.count("\n", 0, offset_or_line) + 1
        if suppressed(lines, line_no - 1, rule.id):
            return
        found.append(Finding(rule.id, rel, line_no, lines[line_no - 1], rule.message, rule.casa))

    for rule in RULES:
        if not matches_files(rule, rel):
            continue
        if rule.custom == "tabnabbing":
            for i, ln in enumerate(lines, 1):
                if re.search(r"target\s*=\s*[\"']_blank", ln) and "noopener" not in ln:
                    add(rule, i, True)
        elif rule.custom == "permissive_deserialize":
            for m in re.finditer(
                r"#\[derive\([^)]*\bDeserialize\b[^)]*\)\]((?:\s*#\[[^\]]*\])*)\s*(?:pub(?:\([^)]*\))?\s+)?struct\b",
                text,
            ):
                if "deny_unknown_fields" not in m.group(1):
                    add(rule, m.start())
        elif rule.custom == "owner_scope":
            for m in re.finditer(r'"(?:[^"\\]|\\.)*"', text, re.S):
                lit = m.group(0)
                if re.search(r"(?i)\b(from|update|into|join)\s+(notes|mail_accounts|mail_messages)\b", lit) \
                        and "owner_id" not in lit:
                    add(rule, m.start())
        elif rule.custom == "cookie_flags":
            for m in re.finditer(r"\bCookie(?:Builder)?::(?:build|new)\s*\((?:(?!;).)*;", text, re.S):
                body = m.group(0)
                if not ("secure(true)" in body and "http_only(true)" in body and "same_site(" in body):
                    add(rule, m.start())
        elif rule.pattern:
            flags = re.S if rule.multiline else 0
            if rule.multiline:
                for m in re.finditer(rule.pattern, text, flags):
                    add(rule, m.start())
            else:
                for i, ln in enumerate(lines, 1):
                    if re.search(rule.pattern, ln):
                        add(rule, i, True)
    return found


def check_env_tracked() -> list[Finding]:
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout
    bad = [f for f in tracked.split("\n")
           if re.search(r"(^|/)\.env(\.|$)", f) and not f.endswith(".env.example")]
    rule = next(r for r in RULES if r.id == "env-file-tracked")
    return [Finding(rule.id, f, 1, f, rule.message, rule.casa) for f in bad]


def cmd_lint(files: list[str]) -> int:
    targets = [f for f in (files or git_files()) if in_scope(f)]
    findings = [f for rel in targets for f in lint_file(rel)]
    if not files:
        findings += check_env_tracked()
    for f in findings:
        print(f, file=sys.stderr)
    print(f"casa-lint: {len(targets)} files, {len(RULES)} rules, {len(findings)} violation(s)",
          file=sys.stderr)
    return 1 if findings else 0


def cmd_hook() -> int:
    if os.environ.get("CASA_IN_REVIEW"):
        return 0
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    path = (payload.get("tool_input") or {}).get("file_path") or ""
    try:
        rel = str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return 0
    if not in_scope(rel):
        return 0
    findings = lint_file(rel)
    if not findings:
        return 0
    print("CASA rule violation in the file you just edited. Fix it before continuing "
          "(see CLAUDE.md; suppress only with a justified `casa-allow`):", file=sys.stderr)
    for f in findings:
        print(f, file=sys.stderr)
    return 2


def test_fn_names() -> set[str]:
    names: set[str] = set()
    for rel in git_files():
        if rel.startswith("backend/src/") and rel.endswith(".rs"):
            names |= set(re.findall(r"\bfn\s+(\w+)", (ROOT / rel).read_text(encoding="utf-8")))
    return names


def cmd_requirements() -> int:
    strict = os.environ.get("CASA_STRICT") == "1"
    errors: list[str] = []
    warnings: list[str] = []
    reg = json.loads(REGISTER.read_text(encoding="utf-8"))
    if reg.get("spec_version") != SPEC_VERSION:
        errors.append(f"register targets spec {reg.get('spec_version')}, checker knows {SPEC_VERSION}")

    reqs = reg["requirements"]
    ids = [r["id"] for r in reqs]
    for missing in sorted(set(SPEC_IDS) - set(ids), key=SPEC_IDS.index):
        errors.append(f"{missing}: missing from register")
    for extra in sorted(set(ids) - set(SPEC_IDS)):
        errors.append(f"{extra}: not a CASA {SPEC_VERSION} audit item")
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        errors.append(f"{dup}: listed more than once")

    fns = test_fn_names()
    corpus = {rel: read(rel) for rel in git_files() if in_scope(rel)}

    def check_evidence(r: dict) -> None:
        for ev in r.get("evidence", []):
            kind, _, ref = ev.partition(":")
            if kind == "test" and ref not in fns:
                errors.append(f"{r['id']}: evidence test '{ref}' does not exist in backend/src")
            elif kind == "lint" and ref not in RULE_IDS:
                errors.append(f"{r['id']}: evidence lint rule '{ref}' does not exist")
            elif kind == "tool" and ref not in TOOLS:
                errors.append(f"{r['id']}: evidence tool '{ref}' is not run by the gate")
            elif kind == "file" and not (ROOT / ref).is_file():
                errors.append(f"{r['id']}: evidence file '{ref}' does not exist")
            elif kind not in {"test", "lint", "tool", "file"}:
                errors.append(f"{r['id']}: unknown evidence kind '{ev}'")

    counts = {"verified": 0, "not_applicable": 0, "pending": 0}
    for r in reqs:
        rid, status = r["id"], r.get("status")
        if status not in counts:
            errors.append(f"{rid}: invalid status {status!r}")
            continue
        counts[status] += 1
        check_evidence(r)
        att = r.get("attestation")
        if att and not all(att.get(k) for k in ("by", "date", "artifact")):
            errors.append(f"{rid}: attestation needs by, date and artifact")
        if status == "verified" and not (r.get("evidence") or att):
            errors.append(f"{rid}: verified without evidence or attestation")
        elif status == "not_applicable":
            if not r.get("reason") or not r.get("reopen_if"):
                errors.append(f"{rid}: not_applicable needs a reason and reopen_if patterns")
            for pat in r.get("reopen_if", []):
                rx = re.compile(pat)
                for rel, text in corpus.items():
                    m = rx.search(text)
                    if m:
                        line = text.count("\n", 0, m.start()) + 1
                        errors.append(
                            f"{rid}: marked not_applicable but '{m.group(0)}' appeared at {rel}:{line}. "
                            f"The requirement now applies: implement and verify it, then update the register.")
                        break
        elif status == "pending":
            if not r.get("blocker"):
                errors.append(f"{rid}: pending needs a blocker description")
            (errors if strict else warnings).append(f"{rid}: PENDING: {r.get('blocker', '')}")

    rendered = render(reg)
    if not CONTROLS_MD.is_file() or CONTROLS_MD.read_text(encoding="utf-8") != rendered:
        errors.append("docs/casa/controls.md is stale: run `python3 scripts/casa_check.py render`")

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    print(f"casa-requirements: {len(SPEC_IDS)} CASA {SPEC_VERSION} items: "
          f"{counts['verified']} verified, {counts['not_applicable']} not applicable, "
          f"{counts['pending']} pending{' (strict: pending fails)' if strict else ''}; "
          f"{len(errors)} error(s)", file=sys.stderr)
    return 1 if errors else 0


def render(reg: dict) -> str:
    icon = {"verified": "✅ verified", "not_applicable": "➖ n/a", "pending": "⏳ pending"}
    out = [
        "<!-- GENERATED by scripts/casa_check.py render from docs/casa/requirements.json. Do not edit. -->",
        "# CASA requirement register",
        "",
        f"Source: [{reg['spec']} v{reg['spec_version']} ({reg['spec_date']})]({reg['spec_url']}). "
        f"Test procedures: [CASA Test Guide]({reg['test_guide_url']}).",
        "",
        "Every audit item is checked on every commit by `scripts/verify.sh`:",
        "- **verified**: the cited tests, lint rules and tools must exist and pass.",
        "- **n/a**: if code matching a reopen pattern appears, the gate fails until the item is re-assessed.",
        "- **pending**: work still owed. Allowed during development, but `CASA_STRICT=1` (release CI) fails.",
        "",
    ]
    counts: dict[str, int] = {}
    for r in reg["requirements"]:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out.append(" · ".join(f"{icon[k]}: **{counts.get(k, 0)}**" for k in icon))
    out.append("")
    by_section: dict[str, list[dict]] = {}
    for r in reg["requirements"]:
        by_section.setdefault(r["id"].split(".")[0], []).append(r)
    for sec, items in by_section.items():
        out += [f"## {sec} {SECTIONS.get(sec, '')}", "",
                "| ID | Requirement | Status | Evidence / notes |", "| --- | --- | --- | --- |"]
        for r in items:
            bits = [f"`{e}`" for e in r.get("evidence", [])]
            if r.get("attestation"):
                a = r["attestation"]
                bits.append(f"attested by {a['by']} on {a['date']}: {a['artifact']}")
            note = r.get("blocker") or r.get("reason") or r.get("notes") or ""
            if note:
                bits.append(note)
            cell = "<br>".join(bits).replace("|", "\\|")
            out.append(f"| {r['id']} | {r['title']} | {icon[r['status']]} | {cell} |")
        out.append("")
    return "\n".join(out)


def cmd_render() -> int:
    CONTROLS_MD.write_text(render(json.loads(REGISTER.read_text(encoding="utf-8"))), encoding="utf-8")
    print(f"wrote {CONTROLS_MD.relative_to(ROOT)}", file=sys.stderr)
    return 0


def cmd_list_rules() -> int:
    for r in RULES:
        print(f"{r.id:28} CASA {', '.join(r.casa):18} {r.message}")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 1
    cmd, rest = argv[0], argv[1:]
    if cmd == "lint":
        return cmd_hook() if rest == ["--hook"] else cmd_lint(rest)
    return {"requirements": cmd_requirements, "render": cmd_render,
            "list-rules": cmd_list_rules}.get(cmd, lambda: (print(__doc__), 1)[1])()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
