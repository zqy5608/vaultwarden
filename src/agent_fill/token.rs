use crate::crypto;

/// Prefix for AI / MCP credentials. These are not Bitwarden user JWTs.
pub const AGENT_TOKEN_PREFIX: &str = "vwagent_";
/// Prefix for the local fill broker. Only this credential can redeem a fill ticket.
pub const FILL_AGENT_TOKEN_PREFIX: &str = "vwfill_";

const TOKEN_BODY_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedCredentialKind {
    Agent,
    FillAgent,
}

/// True for any bearer that uses the agent or fill-agent prefix, including malformed ones.
/// User, organization, and send authenticators must reject these before JWT decoding.
pub fn is_scoped_agent_credential(token: &str) -> bool {
    let token = token.trim();
    token.starts_with(AGENT_TOKEN_PREFIX) || token.starts_with(FILL_AGENT_TOKEN_PREFIX)
}

/// Well-formed scoped credentials only. Malformed prefixes are not accepted by the Agent API.
pub fn scoped_credential_kind(token: &str) -> Option<ScopedCredentialKind> {
    let token = token.trim();
    if let Some(rest) = token.strip_prefix(AGENT_TOKEN_PREFIX)
        && is_token_body(rest)
    {
        return Some(ScopedCredentialKind::Agent);
    }
    if let Some(rest) = token.strip_prefix(FILL_AGENT_TOKEN_PREFIX)
        && is_token_body(rest)
    {
        return Some(ScopedCredentialKind::FillAgent);
    }
    None
}

fn is_token_body(rest: &str) -> bool {
    rest.len() == TOKEN_BODY_LEN && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn agent_api_gate(enabled: bool) -> Result<(), &'static str> {
    if enabled {
        Ok(())
    } else {
        Err("Agent API is disabled")
    }
}

pub fn generate_scoped_token(kind: ScopedCredentialKind) -> String {
    let prefix = match kind {
        ScopedCredentialKind::Agent => AGENT_TOKEN_PREFIX,
        ScopedCredentialKind::FillAgent => FILL_AGENT_TOKEN_PREFIX,
    };
    format!("{prefix}{}", crypto::generate_id::<32>())
}

pub fn token_prefix_label(token: &str) -> String {
    token.chars().take(16).collect()
}

pub fn token_hash(token: &str) -> String {
    crypto::sha256_hex(token.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(prefix: &str) -> String {
        format!("{prefix}{}", "ab".repeat(32))
    }

    #[test]
    fn agent_bearer_cannot_be_a_user_session() {
        let agent = sample(AGENT_TOKEN_PREFIX);
        let fill = sample(FILL_AGENT_TOKEN_PREFIX);
        assert!(is_scoped_agent_credential(&agent));
        assert!(is_scoped_agent_credential(&fill));
        assert_eq!(scoped_credential_kind(&agent), Some(ScopedCredentialKind::Agent));
        assert_eq!(scoped_credential_kind(&fill), Some(ScopedCredentialKind::FillAgent));
        assert!(is_scoped_agent_credential("vwagent_short"));
        assert!(scoped_credential_kind("vwagent_short").is_none());
        assert!(!is_scoped_agent_credential("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"));
        assert!(scoped_credential_kind("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig").is_none());
    }

    #[test]
    fn feature_flag_off_returns_disabled() {
        assert_eq!(agent_api_gate(false), Err("Agent API is disabled"));
        assert!(agent_api_gate(true).is_ok());
    }

    #[test]
    fn generated_tokens_match_their_kind() {
        let agent = generate_scoped_token(ScopedCredentialKind::Agent);
        let fill = generate_scoped_token(ScopedCredentialKind::FillAgent);
        assert_eq!(scoped_credential_kind(&agent), Some(ScopedCredentialKind::Agent));
        assert_eq!(scoped_credential_kind(&fill), Some(ScopedCredentialKind::FillAgent));
        assert_ne!(token_hash(&agent), token_hash(&fill));
        assert!(token_prefix_label(&agent).starts_with(AGENT_TOKEN_PREFIX));
        assert_eq!(token_prefix_label(&agent).chars().count(), 16);
    }
}
