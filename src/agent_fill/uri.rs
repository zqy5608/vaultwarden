use std::net::IpAddr;

use serde_json::Value;
use url::{Host, Url};

/// Bitwarden URI match values. Null is stored as `None` and compared as a strict host match.
pub const MATCH_DOMAIN: i32 = 0;
pub const MATCH_HOST: i32 = 1;
pub const MATCH_STARTS_WITH: i32 = 2;
pub const MATCH_EXACT: i32 = 3;
pub const MATCH_REGEX: i32 = 4;
pub const MATCH_NEVER: i32 = 5;

const MAX_URIS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUri {
    pub uri: String,
    pub match_type: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct OriginPolicy {
    pub allow_ip_literals: bool,
    pub allow_regex: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginDeny {
    Invalid,
    Mismatch,
    IpLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedOrigin {
    pub origin: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub ip_literal: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostKind {
    Name,
    Ipv4,
    Ipv6,
}

/// Bitwarden ciphertext (`2.iv|ct|mac` and the other `N.` encodings). Plaintext URLs do not match.
pub fn looks_like_ciphertext(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 8 {
        return false;
    }
    let Some((prefix, rest)) = value.split_once('.') else {
        return false;
    };
    if prefix.len() != 1 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let rest_ok = rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '|'));
    rest_ok && (rest.contains('|') || rest.len() >= 16)
}

pub fn origin_allowed(
    stored: &[StoredUri],
    target: &str,
    policy: OriginPolicy,
) -> Result<NormalizedOrigin, OriginDeny> {
    let target = normalize_origin(target, false)?;
    if target.ip_literal && !policy.allow_ip_literals {
        return Err(OriginDeny::IpLiteral);
    }
    if stored.is_empty() {
        return Err(OriginDeny::Mismatch);
    }

    for entry in stored {
        if entry_matches(entry, &target, policy) {
            return Ok(target);
        }
    }
    Err(OriginDeny::Mismatch)
}

fn entry_matches(entry: &StoredUri, target: &NormalizedOrigin, policy: OriginPolicy) -> bool {
    match entry.match_type {
        Some(MATCH_NEVER) => false,
        Some(MATCH_REGEX) => policy.allow_regex && regex_matches(&entry.uri, &target.origin),
        other => {
            let Ok(item) = normalize_origin(&entry.uri, true) else {
                return false;
            };
            if item.ip_literal && !policy.allow_ip_literals {
                return false;
            }
            origins_match(&item, target, other)
        }
    }
}

fn origins_match(item: &NormalizedOrigin, target: &NormalizedOrigin, match_type: Option<i32>) -> bool {
    if item.scheme != target.scheme || item.port != target.port {
        return false;
    }
    match match_type {
        None | Some(MATCH_HOST | MATCH_STARTS_WITH | MATCH_EXACT) => item.host == target.host,
        Some(MATCH_DOMAIN) => host_domain_match(&target.host, &item.host),
        _ => false,
    }
}

fn host_domain_match(target: &str, base: &str) -> bool {
    if target == base {
        return true;
    }
    if host_is_ip_like(target) || host_is_ip_like(base) || !base.contains('.') {
        return false;
    }
    let Some(prefix) = target.strip_suffix(base) else {
        return false;
    };
    prefix.ends_with('.') && prefix != "."
}

fn host_is_ip_like(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok() || host.chars().all(|c| c.is_ascii_digit() || c == '.')
}

pub fn normalize_origin(input: &str, allow_schemeless: bool) -> Result<NormalizedOrigin, OriginDeny> {
    let input = input.trim();
    if input.is_empty() || input.len() > 2048 || input.contains('\\') || input.chars().any(char::is_control) {
        return Err(OriginDeny::Invalid);
    }
    if input.chars().any(char::is_whitespace) {
        return Err(OriginDeny::Invalid);
    }

    let owned;
    let with_scheme = if input.contains("://") {
        input
    } else if allow_schemeless {
        owned = format!("https://{input}");
        owned.as_str()
    } else {
        return Err(OriginDeny::Invalid);
    };

    let url = Url::parse(with_scheme).map_err(|_| OriginDeny::Invalid)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(OriginDeny::Invalid);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OriginDeny::Invalid);
    }
    let Some(host) = url.host() else {
        return Err(OriginDeny::Invalid);
    };
    let (host, kind, ip_literal) = host_key(&host).map_err(|()| OriginDeny::Invalid)?;
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(OriginDeny::Invalid);
    }
    let Some(port) = url.port_or_known_default() else {
        return Err(OriginDeny::Invalid);
    };
    let origin = display_origin(url.scheme(), &host, port, kind);
    Ok(NormalizedOrigin {
        origin,
        scheme: url.scheme().to_owned(),
        host,
        port,
        ip_literal,
    })
}

fn host_key(host: &Host<&str>) -> Result<(String, HostKind, bool), ()> {
    match host {
        Host::Domain(domain) => {
            if !domain.is_ascii() || domain.is_empty() {
                return Err(());
            }
            let ip_like = host_is_ip_like(domain) || domain.starts_with("0x") || domain.starts_with("0X");
            Ok(((*domain).to_owned(), HostKind::Name, ip_like))
        }
        Host::Ipv4(ip) => Ok((ip.to_string(), HostKind::Ipv4, true)),
        Host::Ipv6(ip) => Ok((ip.to_string(), HostKind::Ipv6, true)),
    }
}

fn display_origin(scheme: &str, host: &str, port: u16, kind: HostKind) -> String {
    let host_part = match kind {
        HostKind::Ipv6 => format!("[{host}]"),
        HostKind::Name | HostKind::Ipv4 => host.to_owned(),
    };
    let default_port = if scheme == "https" {
        443
    } else {
        80
    };
    if port == default_port {
        format!("{scheme}://{host_part}")
    } else {
        format!("{scheme}://{host_part}:{port}")
    }
}

fn regex_pattern_allowed(pattern: &str) -> bool {
    let pattern = pattern.trim();
    !pattern.is_empty()
        && pattern.len() <= 128
        && !pattern.contains('\n')
        && !pattern.contains(".*")
        && !pattern.contains(".+")
}

fn regex_matches(pattern: &str, origin: &str) -> bool {
    if !regex_pattern_allowed(pattern) {
        return false;
    }
    let pattern = pattern.trim();
    let anchored = if pattern.starts_with('^') && pattern.ends_with('$') {
        pattern.to_owned()
    } else {
        format!("^{pattern}$")
    };
    let Ok(re) = regex::RegexBuilder::new(&anchored).size_limit(1 << 16).dfa_size_limit(1 << 16).nest_limit(20).build()
    else {
        return false;
    };
    re.is_match(origin)
}

/// Index plaintext login URIs from cipher `data`. Encrypted URI blobs are skipped.
/// Regex and "never" matchers are not auto-indexed.
pub fn plaintext_origins_from_login_data(data: &str) -> Vec<StoredUri> {
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    if let Some(uris) = value.get("uris").and_then(Value::as_array) {
        for uri in uris {
            let Some(text) = uri.get("uri").and_then(Value::as_str) else {
                continue;
            };
            if looks_like_ciphertext(text) {
                continue;
            }
            raw.push((text.to_owned(), json_match_type(uri.get("match"))));
        }
    }
    if raw.is_empty()
        && let Some(text) = value.get("uri").and_then(Value::as_str)
        && !looks_like_ciphertext(text)
    {
        raw.push((text.to_owned(), None));
    }

    let mut out = Vec::new();
    for (uri, match_type) in raw {
        if matches!(match_type, Some(MATCH_REGEX | MATCH_NEVER)) {
            continue;
        }
        let Ok(normalized) = normalize_origin(&uri, true) else {
            continue;
        };
        let match_type = match match_type {
            Some(MATCH_DOMAIN | MATCH_HOST | MATCH_STARTS_WITH | MATCH_EXACT) => match_type,
            _ => None,
        };
        push_unique(
            &mut out,
            StoredUri {
                uri: normalized.origin,
                match_type,
            },
        );
        if out.len() == MAX_URIS {
            break;
        }
    }
    out
}

pub fn prepare_index_entries(
    entries: &[(String, Option<i32>)],
    allow_regex: bool,
) -> Result<Vec<StoredUri>, OriginDeny> {
    if entries.len() > MAX_URIS {
        return Err(OriginDeny::Invalid);
    }
    let mut out = Vec::new();
    for (uri, match_type) in entries {
        if looks_like_ciphertext(uri) {
            return Err(OriginDeny::Invalid);
        }
        match match_type {
            Some(MATCH_NEVER) => {}
            Some(MATCH_REGEX) => {
                if !allow_regex || !regex_pattern_allowed(uri) {
                    return Err(OriginDeny::Invalid);
                }
                push_unique(
                    &mut out,
                    StoredUri {
                        uri: uri.trim().to_owned(),
                        match_type: Some(MATCH_REGEX),
                    },
                );
            }
            Some(MATCH_DOMAIN | MATCH_HOST | MATCH_STARTS_WITH | MATCH_EXACT) | None => {
                let normalized = normalize_origin(uri, true)?;
                push_unique(
                    &mut out,
                    StoredUri {
                        uri: normalized.origin,
                        match_type: *match_type,
                    },
                );
            }
            Some(_) => return Err(OriginDeny::Invalid),
        }
    }
    Ok(out)
}

pub fn public_origins(stored: &[StoredUri], allow_ip: bool) -> Vec<String> {
    let mut out = Vec::new();
    for entry in stored {
        if matches!(entry.match_type, Some(MATCH_REGEX | MATCH_NEVER)) {
            continue;
        }
        let Ok(normalized) = normalize_origin(&entry.uri, true) else {
            continue;
        };
        if normalized.ip_literal && !allow_ip {
            continue;
        }
        if !out.iter().any(|existing| existing == &normalized.origin) {
            out.push(normalized.origin);
        }
    }
    out
}

fn push_unique(out: &mut Vec<StoredUri>, entry: StoredUri) {
    if !out.iter().any(|existing| existing.uri == entry.uri && existing.match_type == entry.match_type) {
        out.push(entry);
    }
}

fn json_match_type(value: Option<&Value>) -> Option<i32> {
    match value {
        Some(Value::Number(number)) => number.as_i64().and_then(|n| i32::try_from(n).ok()),
        Some(Value::String(text)) => text.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow_ip: bool, allow_regex: bool) -> OriginPolicy {
        OriginPolicy {
            allow_ip_literals: allow_ip,
            allow_regex,
        }
    }

    fn stored(uri: &str, match_type: Option<i32>) -> StoredUri {
        StoredUri {
            uri: uri.to_owned(),
            match_type,
        }
    }

    #[test]
    fn uri_host_match_is_strict() {
        let item = [stored("https://example.com/login", None)];
        assert!(origin_allowed(&item, "https://example.com", policy(false, false)).is_ok());
        assert!(origin_allowed(&item, "https://example.com/other", policy(false, false)).is_ok());
        assert!(origin_allowed(&item, "https://example.com:443", policy(false, false)).is_ok());
        assert_eq!(
            origin_allowed(&item, "https://login.example.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert_eq!(
            origin_allowed(&item, "https://example.com.evil.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert_eq!(
            origin_allowed(&item, "http://example.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert_eq!(
            origin_allowed(&item, "https://example.com:8443", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert_eq!(origin_allowed(&item, "https://evil.com", policy(false, false)).unwrap_err(), OriginDeny::Mismatch);
    }

    #[test]
    fn domain_match_allows_subdomains_only() {
        let item = [stored("https://example.com", Some(MATCH_DOMAIN))];
        assert!(origin_allowed(&item, "https://login.example.com", policy(false, false)).is_ok());
        assert!(origin_allowed(&item, "https://example.com", policy(false, false)).is_ok());
        assert_eq!(
            origin_allowed(&item, "https://example.com.evil.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert_eq!(
            origin_allowed(&item, "https://notexample.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );

        let narrower = [stored("https://login.example.com", Some(MATCH_DOMAIN))];
        assert_eq!(
            origin_allowed(&narrower, "https://example.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
    }

    #[test]
    fn ip_literals_are_denied_unless_configured() {
        let item = [stored("https://127.0.0.1/login", None)];
        assert_eq!(
            origin_allowed(&item, "https://127.0.0.1", policy(false, false)).unwrap_err(),
            OriginDeny::IpLiteral
        );
        assert!(origin_allowed(&item, "https://127.0.0.1", policy(true, false)).is_ok());
        assert_eq!(origin_allowed(&item, "https://127.0.0.2", policy(true, false)).unwrap_err(), OriginDeny::Mismatch);
        assert_eq!(
            origin_allowed(&[stored("https://example.com", None)], "https://[::1]", policy(false, false)).unwrap_err(),
            OriginDeny::IpLiteral
        );
    }

    #[test]
    fn empty_index_and_regex_deny() {
        assert_eq!(origin_allowed(&[], "https://example.com", policy(false, false)).unwrap_err(), OriginDeny::Mismatch);
        let regex = [stored("https://.*", Some(MATCH_REGEX))];
        assert_eq!(
            origin_allowed(&regex, "https://example.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        let exact = [stored(r"https://example\.com", Some(MATCH_REGEX))];
        assert_eq!(
            origin_allowed(&exact, "https://example.com", policy(false, false)).unwrap_err(),
            OriginDeny::Mismatch
        );
        assert!(origin_allowed(&exact, "https://example.com", policy(false, true)).is_ok());
        assert_eq!(origin_allowed(&exact, "https://evil.com", policy(false, true)).unwrap_err(), OriginDeny::Mismatch);
    }

    #[test]
    fn ciphertext_uris_are_not_indexed() {
        let data = r#"{
            "username":"2.abc|def|ghi",
            "password":"hunter2",
            "totp":"SEEDSECRET",
            "uris":[
                {"uri":"2.ivvalue|ctvalue|macvalue","match":null},
                {"uri":"https://example.com/login?token=sekret","match":null},
                {"uri":"https://user:pass@evil.com","match":null}
            ]
        }"#;
        let indexed = plaintext_origins_from_login_data(data);
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].uri, "https://example.com");
        let rendered = format!("{indexed:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("SEEDSECRET"));
        assert!(!rendered.contains("sekret"));
        assert!(!rendered.contains("pass"));
    }

    #[test]
    fn looks_like_ciphertext_skips_plaintext_urls() {
        assert!(looks_like_ciphertext("2.ivvalue|ctvalue|macvalue"));
        assert!(!looks_like_ciphertext("https://example.com"));
        assert!(!looks_like_ciphertext("alice@example.com"));
        assert!(!looks_like_ciphertext("2.example.com"));
    }
}
