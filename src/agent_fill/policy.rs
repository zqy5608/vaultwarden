use serde_json::{Value, json};

use crate::agent_fill::uri::looks_like_ciphertext;

pub const MAX_LIST: usize = 50;

pub struct AgentItemInput<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub folder_id: Option<&'a str>,
    pub folder_name: Option<&'a str>,
    pub origins: &'a [String],
    pub username: Option<&'a str>,
    pub reprompt: bool,
}

pub struct FillPayloadInput<'a> {
    pub ticket_id: &'a str,
    pub item_id: &'a str,
    pub origin: &'a str,
    pub cipher_key: Option<&'a str>,
    pub data: &'a str,
    pub include_totp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemDeny {
    Used,
    Expired,
    Secret,
    FillAgent,
}

/// Independent facts. A single enum would hide which check failed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemFacts {
    pub redeemed: bool,
    pub expired: bool,
    pub secret_matches: bool,
    pub fill_agent_matches: bool,
}

pub fn evaluate_redeem(facts: RedeemFacts) -> Result<(), RedeemDeny> {
    if !facts.fill_agent_matches {
        return Err(RedeemDeny::FillAgent);
    }
    if facts.redeemed {
        return Err(RedeemDeny::Used);
    }
    if facts.expired {
        return Err(RedeemDeny::Expired);
    }
    if !facts.secret_matches {
        return Err(RedeemDeny::Secret);
    }
    Ok(())
}

pub fn agent_can_see_item(require_folder_acl: bool, allowed_folders: &[String], item_folder: Option<&str>) -> bool {
    if allowed_folders.is_empty() {
        return !require_folder_acl;
    }
    item_folder.is_some_and(|folder| allowed_folders.iter().any(|allowed| allowed == folder))
}

/// Label for the admin folder picker. Ciphertext names stay out of the checkbox text.
pub fn folder_picker_label(name: &str, id: &str) -> String {
    let name = name.trim();
    if !name.is_empty() && !looks_like_ciphertext(name) {
        return name.to_owned();
    }
    let short: String = id.chars().take(8).collect();
    if short.is_empty() {
        "Encrypted folder".to_owned()
    } else {
        format!("Encrypted folder ({short})")
    }
}

pub fn agent_can_fill(visible: bool, reprompt: bool) -> bool {
    visible && !reprompt
}

pub fn plaintext_username(data: &str) -> Option<String> {
    let value: Value = serde_json::from_str(data).ok()?;
    let username = value.get("username")?.as_str()?.trim();
    if username.is_empty() || username.chars().count() > 320 || looks_like_ciphertext(username) {
        return None;
    }
    Some(username.to_owned())
}

pub fn query_matches(
    query: &str,
    name: &str,
    username: Option<&str>,
    origins: &[String],
    folder_name: Option<&str>,
) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return true;
    }
    if query.chars().count() > 200 {
        return false;
    }
    let query = query.to_lowercase();
    let hit = |value: &str| !looks_like_ciphertext(value) && value.to_lowercase().contains(&query);
    hit(name) || username.is_some_and(hit) || origins.iter().any(|origin| hit(origin)) || folder_name.is_some_and(hit)
}

pub fn metadata_json(item: &AgentItemInput<'_>) -> Value {
    let mut body = json!({
        "object": "agentItem",
        "id": item.id,
        "name": clipped_label(item.name),
        "folderId": item.folder_id,
        "uris": item.origins,
        "reprompt": item.reprompt,
    });
    if let Some(folder_name) = item.folder_name.filter(|name| !name.is_empty() && !looks_like_ciphertext(name)) {
        body["folderName"] = json!(folder_name);
    }
    if let Some(username) = item.username.filter(|name| !name.is_empty() && !looks_like_ciphertext(name)) {
        body["username"] = json!(username);
    }
    body
}

pub fn item_list_json(items: &[Value], truncated: bool) -> Value {
    json!({
        "object": "agentItemList",
        "data": items,
        "truncated": truncated,
    })
}

pub fn ticket_created_json(id: &str, expires_at: &str, fill_agent_id: &str) -> Value {
    json!({
        "object": "fillTicket",
        "id": id,
        "status": "pending",
        "expiresAt": expires_at,
        "fillAgentId": fill_agent_id,
    })
}

pub fn ticket_status(redeemed: bool, expired: bool) -> &'static str {
    if redeemed {
        "redeemed"
    } else if expired {
        "expired"
    } else {
        "pending"
    }
}

pub fn ticket_status_json(id: &str, status: &str, expires_at: &str) -> Value {
    json!({
        "object": "fillTicket",
        "id": id,
        "status": status,
        "expiresAt": expires_at,
    })
}

pub fn fill_agent_ticket_json(id: &str, item_id: &str, origin: &str, expires_at: &str, redeem_secret: &str) -> Value {
    json!({
        "object": "fillAgentTicket",
        "id": id,
        "itemId": item_id,
        "origin": origin,
        "expiresAt": expires_at,
        "redeemSecret": redeem_secret,
    })
}

/// Login material for the fill agent only. Every other cipher field is dropped.
pub fn fill_payload_json(input: &FillPayloadInput<'_>) -> Option<Value> {
    let value: Value = serde_json::from_str(input.data).ok()?;
    if !value.is_object() {
        return None;
    }
    let password = value.get("password").and_then(Value::as_str)?;
    let username = value.get("username").and_then(Value::as_str).unwrap_or("");
    let mut login = json!({
        "username": username,
        "password": password,
    });
    if input.include_totp
        && let Some(totp) = value.get("totp").and_then(Value::as_str)
        && !totp.is_empty()
    {
        login["totp"] = json!(totp);
    }
    Some(json!({
        "object": "fillPayload",
        "ticketId": input.ticket_id,
        "itemId": input.item_id,
        "origin": input.origin,
        "key": input.cipher_key,
        "login": login,
    }))
}

fn clipped_label(name: &str) -> Value {
    if name.chars().count() > 2048 {
        Value::Null
    } else {
        json!(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_only_keys(value: &Value, allowed: &[&str]) {
        let object = value.as_object().expect("json object");
        for key in object.keys() {
            assert!(allowed.contains(&key.as_str()), "unexpected key {key}");
        }
    }

    const SECRET_DATA: &str = r#"{
        "username":"alice",
        "password":"hunter2",
        "totp":"SEEDSECRET",
        "notes":"secret note body",
        "ssn":"123-45-6789",
        "number":"4111111111111111",
        "privateKey":"BEGIN-OPENSSH-PRIVATE",
        "fido2Credentials":[{"key":"FIDO2PRIVATE"}],
        "uris":[{"uri":"https://example.com/login","match":null}]
    }"#;

    #[test]
    fn metadata_omits_secrets() {
        let origins = vec!["https://example.com".to_owned()];
        let hidden = metadata_json(&AgentItemInput {
            id: "item-1",
            name: "GitHub",
            folder_id: Some("folder-1"),
            folder_name: Some("2.ivvalue|ctvalue|macvalue"),
            origins: &origins,
            username: None,
            reprompt: false,
        });
        let rendered = hidden.to_string();
        for secret in ["hunter2", "SEEDSECRET", "secret note body", "123-45-6789", "4111111111111111", "FIDO2PRIVATE"] {
            assert!(!rendered.contains(secret), "{secret} leaked into metadata");
        }
        assert_eq!(hidden["object"], "agentItem");
        assert!(hidden.get("login").is_none());
        assert!(hidden.get("notes").is_none());
        assert!(hidden.get("fields").is_none());
        assert!(hidden.get("passwordHistory").is_none());
        assert!(hidden.get("key").is_none());
        assert!(hidden.get("data").is_none());
        assert!(hidden.get("username").is_none());
        assert!(hidden.get("folderName").is_none());
        assert_only_keys(&hidden, &["object", "id", "name", "folderId", "uris", "reprompt"]);

        let revealed = metadata_json(&AgentItemInput {
            id: "item-1",
            name: "GitHub",
            folder_id: Some("folder-1"),
            folder_name: Some("Work"),
            origins: &origins,
            username: Some("alice"),
            reprompt: false,
        });
        assert_eq!(revealed["username"], "alice");
        assert_eq!(revealed["folderName"], "Work");
        assert!(!revealed.to_string().contains("hunter2"));

        let ciphertext_user = metadata_json(&AgentItemInput {
            id: "item-1",
            name: "GitHub",
            folder_id: None,
            folder_name: None,
            origins: &origins,
            username: Some("2.ivvalue|ctvalue|macvalue"),
            reprompt: false,
        });
        assert!(ciphertext_user.get("username").is_none());
    }

    #[test]
    fn metadata_is_not_bitwarden_cipher_details() {
        let origins = vec!["https://example.com".to_owned()];
        let meta = metadata_json(&AgentItemInput {
            id: "item-1",
            name: "GitHub",
            folder_id: None,
            folder_name: None,
            origins: &origins,
            username: Some("alice"),
            reprompt: true,
        });
        assert_ne!(meta["object"], "cipherDetails");
        assert_ne!(meta["object"], "cipher");
        for key in [
            "login",
            "secureNote",
            "card",
            "identity",
            "sshKey",
            "attachments",
            "passwordHistory",
            "notes",
            "fields",
            "key",
        ] {
            assert!(meta.get(key).is_none(), "{key} is a client cipher field");
        }
    }

    #[test]
    fn ticket_create_response_has_no_redeem_secret() {
        let body = ticket_created_json("ticket-1", "2026-11-05T00:00:00.000000Z", "fill-1");
        assert_only_keys(&body, &["object", "id", "status", "expiresAt", "fillAgentId"]);
        assert_eq!(body["status"], "pending");
        assert!(body.get("redeemSecret").is_none());
        assert!(body.get("password").is_none());
        assert!(body.get("secret").is_none());
        assert!(!body.to_string().contains("hunter2"));

        let pending = fill_agent_ticket_json(
            "ticket-1",
            "item-1",
            "https://example.com",
            "2026-11-05T00:00:00Z",
            "redeem-secret",
        );
        assert_eq!(pending["redeemSecret"], "redeem-secret");
        assert!(pending.get("password").is_none());
        assert!(pending.get("login").is_none());
    }

    #[test]
    fn fill_payload_is_login_material_only() {
        let payload = fill_payload_json(&FillPayloadInput {
            ticket_id: "ticket-1",
            item_id: "item-1",
            origin: "https://example.com",
            cipher_key: Some("cipher-key-blob"),
            data: SECRET_DATA,
            include_totp: true,
        })
        .expect("payload");
        assert_eq!(payload["login"]["password"], "hunter2");
        assert_eq!(payload["login"]["username"], "alice");
        assert_eq!(payload["login"]["totp"], "SEEDSECRET");
        assert_eq!(payload["key"], "cipher-key-blob");
        assert_only_keys(&payload, &["object", "ticketId", "itemId", "origin", "key", "login"]);
        assert_only_keys(&payload["login"], &["username", "password", "totp"]);
        let rendered = payload.to_string();
        for secret in ["secret note body", "123-45-6789", "4111111111111111", "FIDO2PRIVATE", "BEGIN-OPENSSH-PRIVATE"] {
            assert!(!rendered.contains(secret), "{secret} leaked into fill payload");
        }

        let without_totp = fill_payload_json(&FillPayloadInput {
            ticket_id: "ticket-1",
            item_id: "item-1",
            origin: "https://example.com",
            cipher_key: None,
            data: SECRET_DATA,
            include_totp: false,
        })
        .expect("payload");
        assert!(without_totp["login"].get("totp").is_none());
        assert!(!without_totp.to_string().contains("SEEDSECRET"));
    }

    struct TicketState {
        secret: Option<String>,
        redeemed: bool,
        expired: bool,
        fill_agent_ok: bool,
    }

    impl TicketState {
        /// Same transition the database claim must perform: one success, then the secret is gone.
        fn redeem(&mut self, secret: &str) -> Result<(), RedeemDeny> {
            let secret_matches = self.secret.as_deref().is_some_and(|expected| crate::crypto::ct_eq(expected, secret));
            evaluate_redeem(RedeemFacts {
                redeemed: self.redeemed,
                expired: self.expired,
                secret_matches,
                fill_agent_matches: self.fill_agent_ok,
            })?;
            self.redeemed = true;
            self.secret = None;
            Ok(())
        }
    }

    #[test]
    fn ticket_is_single_use() {
        let mut ticket = TicketState {
            secret: Some("one-time".to_owned()),
            redeemed: false,
            expired: false,
            fill_agent_ok: true,
        };
        assert!(ticket.redeem("one-time").is_ok());
        assert!(ticket.secret.is_none());
        assert!(ticket.redeemed);
        assert_eq!(ticket.redeem("one-time"), Err(RedeemDeny::Used));
        assert_eq!(
            evaluate_redeem(RedeemFacts {
                redeemed: false,
                expired: true,
                secret_matches: true,
                fill_agent_matches: true,
            }),
            Err(RedeemDeny::Expired)
        );
        assert_eq!(
            evaluate_redeem(RedeemFacts {
                redeemed: false,
                expired: false,
                secret_matches: false,
                fill_agent_matches: true,
            }),
            Err(RedeemDeny::Secret)
        );
        assert_eq!(
            evaluate_redeem(RedeemFacts {
                redeemed: false,
                expired: false,
                secret_matches: true,
                fill_agent_matches: false,
            }),
            Err(RedeemDeny::FillAgent)
        );
    }

    #[test]
    fn folder_acl_hides_items_outside_the_allowlist() {
        assert!(!agent_can_see_item(true, &[], Some("folder-1")));
        assert!(!agent_can_see_item(true, &[], None));
        assert!(agent_can_see_item(false, &[], Some("folder-1")));
        assert!(agent_can_see_item(false, &[], None));
        let allowed = vec!["folder-1".to_owned()];
        assert!(agent_can_see_item(true, &allowed, Some("folder-1")));
        assert!(!agent_can_see_item(true, &allowed, Some("folder-2")));
        assert!(!agent_can_see_item(true, &allowed, None));
        assert!(agent_can_see_item(false, &allowed, Some("folder-1")));
        assert!(!agent_can_see_item(false, &allowed, Some("folder-2")));
        assert!(!agent_can_see_item(false, &allowed, None));
        assert!(!agent_can_fill(false, false));
        assert!(!agent_can_fill(true, true));
        assert!(agent_can_fill(true, false));
    }

    #[test]
    fn folder_picker_label_uses_plaintext_names() {
        assert_eq!(folder_picker_label("Work", "11111111-2222-3333-4444-555555555555"), "Work");
        assert_eq!(folder_picker_label("  Personal  ", "11111111-2222-3333-4444-555555555555"), "Personal");
        assert_eq!(
            folder_picker_label("2.ivvalue|ctvalue|macvalue", "abcdef12-2222-3333-4444-555555555555"),
            "Encrypted folder (abcdef12)"
        );
        assert_eq!(folder_picker_label("   ", "abcdef12-2222-3333-4444-555555555555"), "Encrypted folder (abcdef12)");
        assert_eq!(folder_picker_label("", ""), "Encrypted folder");
    }

    #[test]
    fn query_does_not_match_ciphertext_or_hidden_usernames() {
        let origins = vec!["https://example.com".to_owned()];
        assert!(query_matches("github", "GitHub", None, &origins, None));
        assert!(!query_matches("alice", "2.ivvalue|ctvalue|macvalue", None, &origins, None));
        assert!(query_matches("alice", "GitHub", Some("alice"), &origins, None));
        assert!(!query_matches("hunter2", "GitHub", Some("alice"), &origins, None));
        assert!(!query_matches(&"x".repeat(201), "GitHub", None, &origins, None));
    }

    #[test]
    fn plaintext_username_drops_ciphertext() {
        assert_eq!(plaintext_username(SECRET_DATA).as_deref(), Some("alice"));
        assert!(plaintext_username(r#"{"username":"2.ivvalue|ctvalue|macvalue","password":"hunter2"}"#).is_none());
    }
}
