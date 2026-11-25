//! Turns what the Compose form sends into the email Gmail is asked to send.
//!
//! Everything here is request input that ends up in mail headers, so the
//! rule is: nothing reaches a header unless it is checked first (mail header
//! injection; CASA 5.1.x covers injection in general).
//! - Addresses are bare `local@domain` in a narrow ASCII alphabet: no display
//!   names, quotes, spaces, or line breaks.
//! - The subject is refused if it has control characters, and is sent as
//!   RFC 2047 encoded words unless it is plain ASCII.
//! - The body is base64, so nothing in it can be read as a header or as
//!   another MIME part.
//!
//! `From` is the linked mailbox's own address, from our database, never from
//! the request. Gmail adds `Date` and `Message-ID`, and delivers to `Bcc`
//! without showing it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Most recipients in To, Cc and Bcc together.
pub const MAX_RECIPIENTS: usize = 50;
pub const MAX_SUBJECT_CHARS: usize = 255;
pub const MAX_BODY_CHARS: usize = 100_000;
/// RFC 5321: 64 for the part before the `@`, 254 in all.
const MAX_ADDRESS_LEN: usize = 254;
const MAX_LOCAL_LEN: usize = 64;
/// Base64 characters per body line (RFC 2045: lines of at most 76).
const BODY_LINE: usize = 76;
/// Subject bytes per encoded word, so each stays under 75 characters.
const SUBJECT_CHUNK: usize = 39;

/// A message as the form gives it.
pub struct Draft<'a> {
    pub to: &'a [String],
    pub cc: &'a [String],
    pub bcc: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
}

/// What is wrong with a draft, in words for the person writing it. Never
/// repeats their input back.
#[derive(Debug, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

/// The message as RFC 5322 text, ready for Gmail's `raw` field (which wants
/// it base64url-encoded: `auth::google` does that).
pub fn build(from: &str, draft: &Draft<'_>) -> Result<String, Invalid> {
    if !valid_address(from) {
        return Err(Invalid("This mailbox's address can't be used to send."));
    }
    let count = draft.to.len() + draft.cc.len() + draft.bcc.len();
    if count == 0 {
        return Err(Invalid("Add at least one recipient."));
    }
    if count > MAX_RECIPIENTS {
        return Err(Invalid("Too many recipients (50 at most)."));
    }
    let all = draft.to.iter().chain(draft.cc).chain(draft.bcc);
    if !all.into_iter().all(|a| valid_address(a)) {
        return Err(Invalid("One of the addresses isn't a valid email address."));
    }
    if draft.subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(Invalid("The subject is too long (255 characters at most)."));
    }
    if draft.subject.chars().any(char::is_control) {
        return Err(Invalid("The subject can't contain line breaks."));
    }
    if draft.body.chars().count() > MAX_BODY_CHARS {
        return Err(Invalid(
            "The message is too long (100,000 characters at most).",
        ));
    }

    let mut out = String::new();
    out.push_str("From: ");
    out.push_str(from);
    out.push_str("\r\n");
    for (name, addresses) in [("To", draft.to), ("Cc", draft.cc), ("Bcc", draft.bcc)] {
        if !addresses.is_empty() {
            out.push_str(name);
            out.push_str(": ");
            // One address per line: no header line gets long.
            out.push_str(&addresses.join(",\r\n "));
            out.push_str("\r\n");
        }
    }
    out.push_str("Subject: ");
    out.push_str(&encode_subject(draft.subject));
    out.push_str("\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    out.push_str("Content-Transfer-Encoding: base64\r\n");
    out.push_str("\r\n");
    let body = STANDARD.encode(normalize_newlines(draft.body));
    // Base64 is ASCII, so any byte offset is a character boundary.
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(BODY_LINE));
        out.push_str(line);
        out.push_str("\r\n");
        rest = tail;
    }
    Ok(out)
}

/// A bare email address in the alphabet nearly all real ones use. Stricter
/// than RFC 5322 on purpose: no quoted local parts, comments, display names
/// or non-ASCII, and nothing that could end a header line.
pub fn valid_address(address: &str) -> bool {
    if address.len() > MAX_ADDRESS_LEN {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= MAX_LOCAL_LEN
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&b));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    local_ok && domain_ok
}

/// Plain if it is printable ASCII, otherwise RFC 2047 encoded words (UTF-8,
/// base64), split between characters and folded onto continuation lines.
/// Control characters were refused before this.
fn encode_subject(subject: &str) -> String {
    if subject.bytes().all(|b| (b' '..=b'~').contains(&b)) {
        return subject.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in subject.chars() {
        if chunk.len() + c.len_utf8() > SUBJECT_CHUNK {
            words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&chunk)));
    }
    words.join("\r\n ")
}

/// Every line break as CRLF, as mail wants it.
fn normalize_newlines(body: &str) -> String {
    body.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn list(addresses: &[&str]) -> Vec<String> {
        addresses.iter().map(|a| (*a).to_owned()).collect()
    }

    fn draft<'a>(to: &'a [String], subject: &'a str, body: &'a str) -> Draft<'a> {
        Draft {
            to,
            cc: &[],
            bcc: &[],
            subject,
            body,
        }
    }

    /// Splits a built message into its header lines (unfolded) and body.
    fn parts(message: &str) -> (Vec<String>, String) {
        let (head, body) = message.split_once("\r\n\r\n").unwrap();
        let headers = head
            .replace("\r\n ", " ")
            .split("\r\n")
            .map(str::to_owned)
            .collect();
        let decoded = STANDARD.decode(body.replace("\r\n", "")).unwrap();
        (headers, String::from_utf8(decoded).unwrap())
    }

    #[test]
    fn a_draft_becomes_a_plain_text_message_from_the_mailbox() {
        let to = list(&["ada@example.com", "bob@example.org"]);
        let cc = list(&["cy@example.net"]);
        let bcc = list(&["dee@example.com"]);
        let message = build(
            "me@example.com",
            &Draft {
                to: &to,
                cc: &cc,
                bcc: &bcc,
                subject: "Lunch on Friday?",
                body: "Hi both,\n\nNoon works for me.\n",
            },
        )
        .unwrap();
        let (headers, body) = parts(&message);
        assert_eq!(
            headers,
            [
                "From: me@example.com",
                "To: ada@example.com, bob@example.org",
                "Cc: cy@example.net",
                "Bcc: dee@example.com",
                "Subject: Lunch on Friday?",
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=UTF-8",
                "Content-Transfer-Encoding: base64",
            ]
        );
        assert_eq!(body, "Hi both,\r\n\r\nNoon works for me.\r\n");
        assert!(message.split("\r\n").all(|line| line.len() <= 78));
    }

    #[test]
    fn nothing_in_a_draft_can_add_a_header_or_a_recipient() {
        // Mail header injection: request input goes into headers, so a line break
        // (or anything that isn't a bare address) must never get there.
        let ok = list(&["ada@example.com"]);
        for bad in [
            "ada@example.com\r\nBcc: spy@evil.example",
            "ada@example.com\nBcc: spy@evil.example",
            "ada@example.com, spy@evil.example",
            "Ada <ada@example.com>",
            "\"a b\"@example.com",
            "ada@example.com ",
            "ada@@example.com",
            "ada@localhost",
            "ada@-bad.example",
            ".ada@example.com",
            "ad..a@example.com",
            "adä@example.com",
            "@example.com",
            "ada",
            "",
        ] {
            assert!(!valid_address(bad), "accepted {bad:?}");
            let to = list(&[bad]);
            assert!(build("me@example.com", &draft(&to, "s", "b")).is_err());
            assert!(build(bad, &draft(&ok, "s", "b")).is_err());
        }
        for subject in [
            "Hi\r\nBcc: spy@evil.example",
            "Hi\nthere",
            "tab\there",
            "nul\0",
        ] {
            assert!(
                build("me@example.com", &draft(&ok, subject, "b")).is_err(),
                "accepted subject {subject:?}"
            );
        }
        // The body can say anything: it is base64, so it stays the body.
        let body = "\r\n\r\nBcc: spy@evil.example\r\n--boundary\r\n";
        let message = build("me@example.com", &draft(&ok, "s", body)).unwrap();
        let (headers, decoded) = parts(&message);
        assert_eq!(headers.len(), 6);
        assert!(!message.contains("spy@evil.example"));
        assert_eq!(decoded, body);
    }

    #[test]
    fn drafts_must_have_a_recipient_and_stay_within_limits() {
        let ok = list(&["ada@example.com"]);
        let none: Vec<String> = Vec::new();
        assert!(build("me@example.com", &draft(&none, "s", "b")).is_err());
        // Bcc alone is enough.
        let only_bcc = Draft {
            to: &none,
            cc: &none,
            bcc: &ok,
            subject: "",
            body: "",
        };
        assert!(build("me@example.com", &only_bcc).is_ok());

        let many: Vec<String> = (0..=MAX_RECIPIENTS)
            .map(|i| format!("p{i}@example.com"))
            .collect();
        assert!(build("me@example.com", &draft(&many, "s", "b")).is_err());
        assert!(build("me@example.com", &draft(&many[1..], "s", "b")).is_ok());

        let long_subject = "s".repeat(MAX_SUBJECT_CHARS + 1);
        assert!(build("me@example.com", &draft(&ok, &long_subject, "b")).is_err());
        let long_body = "b".repeat(MAX_BODY_CHARS + 1);
        assert!(build("me@example.com", &draft(&ok, "s", &long_body)).is_err());
        assert!(build("me@example.com", &draft(&ok, "s", &long_body[1..])).is_ok());
    }

    #[test]
    fn subjects_outside_ascii_are_sent_as_encoded_words() {
        let ok = list(&["ada@example.com"]);
        let subject = "Réunion à 15h — 日本語のテスト ".repeat(6);
        let subject = subject.trim_end();
        let message = build("me@example.com", &draft(&ok, subject, "b")).unwrap();
        let (head, _) = message.split_once("\r\n\r\n").unwrap();
        assert!(head.is_ascii());
        assert!(message.split("\r\n").all(|line| line.len() <= 78));
        let line = parts(&message)
            .0
            .into_iter()
            .find(|h| h.starts_with("Subject: "))
            .unwrap();
        let decoded: Vec<u8> = line["Subject: ".len()..]
            .split(' ')
            .flat_map(|word| {
                let b64 = word
                    .strip_prefix("=?UTF-8?B?")
                    .and_then(|w| w.strip_suffix("?="))
                    .unwrap();
                STANDARD.decode(b64).unwrap()
            })
            .collect();
        assert_eq!(String::from_utf8(decoded).unwrap(), subject);
    }
}
