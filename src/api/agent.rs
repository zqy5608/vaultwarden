use std::collections::HashMap;

use rocket::{Route, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    agent_fill::{
        AgentItemInput, FillPayloadInput, OriginDeny, OriginPolicy, RedeemFacts, ScopedCredentialKind, StoredUri,
        agent_api_gate, agent_can_fill, agent_can_see_item, evaluate_redeem, fill_agent_ticket_json, fill_payload_json,
        item_list_json, metadata_json, normalize_origin, origin_allowed, plaintext_username, public_origins,
        query_matches, scoped_credential_kind, ticket_created_json, ticket_status, ticket_status_json,
    },
    api::JsonResult,
    auth::{ClientIp, Headers},
    crypto,
    db::{
        DbConn,
        models::{
            AgentAudit, AgentCipherUri, AgentToken, AgentTokenFolder, AgentTokenId, Cipher, CipherId, FillAgent,
            FillAgentId, FillTicket, FillTicketId, Folder, FolderCipher, FolderId, RepromptType, UserId,
            find_personal_login, find_personal_logins,
        },
    },
    util::format_date,
};

/// Fill-only API for untrusted AI clients.
///
/// AI tokens (`vwagent_`) receive metadata and a ticket id. The redeem secret and
/// login material are returned only to a registered fill agent (`vwfill_`).
pub fn routes() -> Vec<Route> {
    routes![list_items, create_fill, fill_status, pending_fills, redeem_fill, put_uri_index, delete_uri_index]
}

pub struct PresentedBearer(pub Option<String>);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for PresentedBearer {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("Authorization").and_then(|header| {
            let rest = header.trim().strip_prefix("Bearer ").or_else(|| header.trim().strip_prefix("bearer "))?;
            let rest = rest.trim();
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_owned())
            }
        });
        rocket::request::Outcome::Success(PresentedBearer(token))
    }
}

fn ensure_enabled() -> Result<(), crate::Error> {
    match agent_api_gate(CONFIG.agent_api_enabled()) {
        Ok(()) => Ok(()),
        Err(message) => Err(crate::Error::new_msg(message).with_code(403)),
    }
}

fn unauthorized() -> crate::Error {
    crate::Error::new_msg("Unauthorized").with_code(401)
}

fn denied(message: &'static str) -> crate::Error {
    crate::Error::new_msg(message).with_code(400)
}

fn origin_policy() -> OriginPolicy {
    OriginPolicy {
        allow_ip_literals: CONFIG.agent_allow_ip_origins(),
        allow_regex: CONFIG.agent_allow_regex_uri_match(),
    }
}

fn is_reprompt(cipher: &Cipher) -> bool {
    cipher.reprompt == Some(RepromptType::Password as i32)
}

fn parse_uuid_id<T: From<String>>(value: &str) -> Option<T> {
    uuid::Uuid::parse_str(value).ok()?;
    Some(T::from(value.to_owned()))
}

async fn require_agent(bearer: &PresentedBearer, conn: &DbConn) -> Result<AgentToken, crate::Error> {
    let raw = bearer.0.as_deref().ok_or_else(unauthorized)?;
    if scoped_credential_kind(raw) != Some(ScopedCredentialKind::Agent) {
        return Err(unauthorized());
    }
    let Some(token) = AgentToken::find_active_by_hash(&crate::agent_fill::token_hash(raw), conn).await else {
        return Err(unauthorized());
    };
    let Some(user) = crate::db::models::User::find_by_uuid(&token.user_uuid, conn).await else {
        return Err(unauthorized());
    };
    if !user.enabled {
        return Err(unauthorized());
    }
    token.touch(conn).await;
    Ok(token)
}

async fn require_fill_agent(bearer: &PresentedBearer, conn: &DbConn) -> Result<FillAgent, crate::Error> {
    let raw = bearer.0.as_deref().ok_or_else(unauthorized)?;
    if scoped_credential_kind(raw) != Some(ScopedCredentialKind::FillAgent) {
        return Err(unauthorized());
    }
    let Some(agent) = FillAgent::find_active_by_hash(&crate::agent_fill::token_hash(raw), conn).await else {
        return Err(unauthorized());
    };
    let Some(user) = crate::db::models::User::find_by_uuid(&agent.user_uuid, conn).await else {
        return Err(unauthorized());
    };
    if !user.enabled {
        return Err(unauthorized());
    }
    agent.touch(conn).await;
    Ok(agent)
}

#[allow(clippy::too_many_arguments)]
async fn audit(
    user: &UserId,
    agent: Option<&AgentTokenId>,
    fill: Option<&FillAgentId>,
    cipher: Option<&CipherId>,
    action: &'static str,
    origin: Option<String>,
    detail: &'static str,
    ip: &ClientIp,
    conn: &DbConn,
) {
    AgentAudit::record(
        user.clone(),
        agent.cloned(),
        fill.cloned(),
        cipher.cloned(),
        action,
        origin,
        detail,
        Some(ip.ip.to_string()),
        conn,
    )
    .await;
}

async fn audit_ticket_deny(
    fill_agent: &FillAgent,
    ticket: &FillTicket,
    detail: &'static str,
    ip: &ClientIp,
    conn: &DbConn,
) {
    audit(
        &fill_agent.user_uuid,
        Some(&ticket.agent_token_uuid),
        Some(&fill_agent.uuid),
        Some(&ticket.cipher_uuid),
        "deny",
        Some(ticket.origin.clone()),
        detail,
        ip,
        conn,
    )
    .await;
}

struct ItemContext {
    folder_by_cipher: HashMap<CipherId, FolderId>,
    folder_names: HashMap<FolderId, String>,
    uris_by_cipher: HashMap<CipherId, Vec<StoredUri>>,
    allowed_folders: Vec<String>,
}

async fn load_context(user_uuid: &UserId, token_uuid: &AgentTokenId, ciphers: &[Cipher], conn: &DbConn) -> ItemContext {
    let mut folder_by_cipher = HashMap::new();
    for (cipher_id, folder_id) in FolderCipher::find_by_user(user_uuid, conn).await {
        folder_by_cipher.insert(cipher_id, folder_id);
    }
    let folder_names =
        Folder::find_by_user(user_uuid, conn).await.into_iter().map(|folder| (folder.uuid, folder.name)).collect();
    let ids: Vec<CipherId> = ciphers.iter().map(|cipher| cipher.uuid.clone()).collect();
    let mut uris_by_cipher: HashMap<CipherId, Vec<StoredUri>> = HashMap::new();
    for (cipher_id, uri) in AgentCipherUri::find_for_ciphers(&ids, conn).await {
        uris_by_cipher.entry(cipher_id).or_default().push(uri);
    }
    let allowed_folders = AgentTokenFolder::folders_for_token(token_uuid, conn)
        .await
        .into_iter()
        .map(|folder_id| folder_id.as_ref().clone())
        .collect();
    ItemContext {
        folder_by_cipher,
        folder_names,
        uris_by_cipher,
        allowed_folders,
    }
}

fn folder_of<'a>(context: &'a ItemContext, cipher_id: &CipherId) -> (Option<&'a str>, Option<&'a str>) {
    let folder_id = context.folder_by_cipher.get(cipher_id);
    let folder_name = folder_id.and_then(|id| context.folder_names.get(id)).map(String::as_str);
    (folder_id.map(|id| id.as_ref().as_str()), folder_name)
}

fn stored_uris<'a>(context: &'a ItemContext, cipher_id: &CipherId) -> &'a [StoredUri] {
    context.uris_by_cipher.get(cipher_id).map_or(&[], Vec::as_slice)
}

fn visible(context: &ItemContext, cipher: &Cipher) -> bool {
    let (folder_id, _) = folder_of(context, &cipher.uuid);
    agent_can_see_item(CONFIG.agent_require_folder_acl(), &context.allowed_folders, folder_id)
}

#[get("/agent/items?<url>&<q>")]
async fn list_items(
    url: Option<String>,
    q: Option<String>,
    bearer: PresentedBearer,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    ensure_enabled()?;
    let token = require_agent(&bearer, &conn).await?;
    let target = match url.as_deref() {
        None => None,
        Some(url) => Some(normalize_origin(url, false).map_err(|_| denied("Invalid origin"))?),
    };
    let ciphers = find_personal_logins(&token.user_uuid, &conn).await;
    let context = load_context(&token.user_uuid, &token.uuid, &ciphers, &conn).await;
    let mut items = Vec::new();
    for cipher in &ciphers {
        if !visible(&context, cipher) {
            continue;
        }
        let stored = stored_uris(&context, &cipher.uuid);
        if let Some(target) = &target
            && origin_allowed(stored, &target.origin, origin_policy()).is_err()
        {
            continue;
        }
        let origins = public_origins(stored, CONFIG.agent_allow_ip_origins());
        let (folder_id, folder_name) = folder_of(&context, &cipher.uuid);
        let username = CONFIG.agent_reveal_usernames().then(|| plaintext_username(&cipher.data)).flatten();
        let query = q.as_deref().unwrap_or("");
        if !query_matches(query, &cipher.name, username.as_deref(), &origins, folder_name) {
            continue;
        }
        items.push(metadata_json(&AgentItemInput {
            id: cipher.uuid.as_ref(),
            name: &cipher.name,
            folder_id,
            folder_name,
            origins: &origins,
            username: username.as_deref(),
            reprompt: is_reprompt(cipher),
        }));
    }
    items.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let truncated = items.len() > crate::agent_fill::MAX_LIST;
    items.truncate(crate::agent_fill::MAX_LIST);
    audit(
        &token.user_uuid,
        Some(&token.uuid),
        None,
        None,
        "match",
        target.map(|origin| origin.origin),
        "listed",
        &ip,
        &conn,
    )
    .await;
    Ok(Json(item_list_json(&items, truncated)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FillCreateBody {
    item_id: String,
    origin: String,
    fill_agent_id: String,
}

#[post("/agent/fills", data = "<body>")]
async fn create_fill(body: Json<FillCreateBody>, bearer: PresentedBearer, ip: ClientIp, conn: DbConn) -> JsonResult {
    ensure_enabled()?;
    let token = require_agent(&bearer, &conn).await?;
    let Some(cipher_id) = parse_uuid_id::<CipherId>(&body.item_id) else {
        return Err(denied("Item not available"));
    };
    let Some(fill_agent_id) = parse_uuid_id::<FillAgentId>(&body.fill_agent_id) else {
        audit(&token.user_uuid, Some(&token.uuid), None, None, "deny", None, "deny_fill_agent", &ip, &conn).await;
        return Err(denied("Fill agent not available"));
    };
    let Some(fill_agent) = FillAgent::find_active_by_id(&fill_agent_id, &token.user_uuid, &conn).await else {
        audit(&token.user_uuid, Some(&token.uuid), None, None, "deny", None, "deny_fill_agent", &ip, &conn).await;
        return Err(denied("Fill agent not available"));
    };
    let Some(cipher) = find_personal_login(&cipher_id, &token.user_uuid, &conn).await else {
        audit(&token.user_uuid, Some(&token.uuid), Some(&fill_agent.uuid), None, "deny", None, "deny_item", &ip, &conn)
            .await;
        return Err(denied("Item not available"));
    };
    let context = load_context(&token.user_uuid, &token.uuid, std::slice::from_ref(&cipher), &conn).await;
    if !visible(&context, &cipher) || !agent_can_fill(true, is_reprompt(&cipher)) {
        audit(
            &token.user_uuid,
            Some(&token.uuid),
            Some(&fill_agent.uuid),
            Some(&cipher.uuid),
            "deny",
            None,
            "deny_item",
            &ip,
            &conn,
        )
        .await;
        return Err(denied("Item not available"));
    }
    let stored = stored_uris(&context, &cipher.uuid);
    let normalized = match origin_allowed(stored, &body.origin, origin_policy()) {
        Ok(origin) => origin,
        Err(OriginDeny::Invalid) => {
            audit(
                &token.user_uuid,
                Some(&token.uuid),
                Some(&fill_agent.uuid),
                Some(&cipher.uuid),
                "deny",
                None,
                "deny_origin",
                &ip,
                &conn,
            )
            .await;
            return Err(denied("Invalid origin"));
        }
        Err(_) => {
            audit(
                &token.user_uuid,
                Some(&token.uuid),
                Some(&fill_agent.uuid),
                Some(&cipher.uuid),
                "deny",
                None,
                "deny_origin",
                &ip,
                &conn,
            )
            .await;
            return Err(denied("Origin not allowed"));
        }
    };
    let ttl = i64::from(CONFIG.agent_fill_ticket_ttl_secs());
    let Some(delta) = chrono::TimeDelta::try_seconds(ttl) else {
        return Err(crate::Error::new_msg("Invalid ticket lifetime").with_code(500));
    };
    let expires_at = chrono::Utc::now().naive_utc() + delta;
    let redeem_secret = crypto::generate_id::<32>();
    let ticket = FillTicket::create(
        redeem_secret,
        token.uuid.clone(),
        fill_agent.uuid.clone(),
        token.user_uuid.clone(),
        cipher.uuid.clone(),
        normalized.origin.clone(),
        expires_at,
        &conn,
    )
    .await?;
    audit(
        &token.user_uuid,
        Some(&token.uuid),
        Some(&fill_agent.uuid),
        Some(&cipher.uuid),
        "ticket_create",
        Some(normalized.origin),
        "created",
        &ip,
        &conn,
    )
    .await;
    Ok(Json(ticket_created_json(ticket.uuid.as_ref(), &format_date(&ticket.expires_at), fill_agent.uuid.as_ref())))
}

#[get("/agent/fills/<ticket_id>")]
async fn fill_status(ticket_id: FillTicketId, bearer: PresentedBearer, conn: DbConn) -> JsonResult {
    ensure_enabled()?;
    let token = require_agent(&bearer, &conn).await?;
    let Some(ticket) = FillTicket::find_by_uuid(&ticket_id, &conn).await else {
        return Err(denied("Ticket not available"));
    };
    if ticket.agent_token_uuid != token.uuid || ticket.user_uuid != token.user_uuid {
        return Err(denied("Ticket not available"));
    }
    let expired = ticket.expires_at <= chrono::Utc::now().naive_utc();
    let status = ticket_status(ticket.redeemed_at.is_some(), expired);
    Ok(Json(ticket_status_json(ticket.uuid.as_ref(), status, &format_date(&ticket.expires_at))))
}

#[get("/agent/fill-agent/pending")]
async fn pending_fills(bearer: PresentedBearer, conn: DbConn) -> JsonResult {
    ensure_enabled()?;
    let fill_agent = require_fill_agent(&bearer, &conn).await?;
    let tickets = FillTicket::list_pending_for_fill_agent(&fill_agent.uuid, &conn).await;
    let data: Vec<Value> = tickets
        .iter()
        .map(|ticket| {
            fill_agent_ticket_json(
                ticket.uuid.as_ref(),
                ticket.cipher_uuid.as_ref(),
                &ticket.origin,
                &format_date(&ticket.expires_at),
                &ticket.redeem_secret,
            )
        })
        .collect();
    Ok(Json(json!({
        "object": "fillAgentTicketList",
        "data": data,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RedeemBody {
    ticket_id: String,
    secret: String,
}

#[post("/agent/fill-agent/redeem", data = "<body>")]
async fn redeem_fill(body: Json<RedeemBody>, bearer: PresentedBearer, ip: ClientIp, conn: DbConn) -> JsonResult {
    ensure_enabled()?;
    let fill_agent = require_fill_agent(&bearer, &conn).await?;
    if body.secret.len() > 128 {
        return Err(denied("Ticket not available"));
    }
    let Some(ticket_id) = parse_uuid_id::<FillTicketId>(&body.ticket_id) else {
        return Err(denied("Ticket not available"));
    };
    let Some(ticket) = FillTicket::find_by_uuid(&ticket_id, &conn).await else {
        return Err(denied("Ticket not available"));
    };
    if ticket.user_uuid != fill_agent.user_uuid {
        return Err(denied("Ticket not available"));
    }
    let expired = ticket.expires_at <= chrono::Utc::now().naive_utc();
    let secret_matches = crypto::ct_eq(&ticket.redeem_secret, body.secret.as_str());
    let fill_agent_matches = ticket.fill_agent_uuid == fill_agent.uuid;
    if evaluate_redeem(RedeemFacts {
        redeemed: ticket.redeemed_at.is_some(),
        expired,
        secret_matches,
        fill_agent_matches,
    })
    .is_err()
    {
        audit(
            &fill_agent.user_uuid,
            Some(&ticket.agent_token_uuid),
            Some(&fill_agent.uuid),
            Some(&ticket.cipher_uuid),
            "deny",
            Some(ticket.origin.clone()),
            "deny_ticket",
            &ip,
            &conn,
        )
        .await;
        return Err(denied("Ticket not available"));
    }
    // Atomic single-use claim. A second caller loses here even if it passed the check above.
    let claimed = FillTicket::claim_redeem(&ticket.uuid, &conn).await?;
    if !claimed {
        audit_ticket_deny(&fill_agent, &ticket, "deny_ticket", &ip, &conn).await;
        return Err(denied("Ticket not available"));
    }

    let Some(agent_token) = AgentToken::find_by_uuid(&ticket.agent_token_uuid, &conn).await else {
        audit_ticket_deny(&fill_agent, &ticket, "deny_item", &ip, &conn).await;
        return Err(denied("Item not available"));
    };
    if agent_token.revoked_at.is_some() {
        audit_ticket_deny(&fill_agent, &ticket, "deny_item", &ip, &conn).await;
        return Err(denied("Item not available"));
    }
    let Some(cipher) = find_personal_login(&ticket.cipher_uuid, &fill_agent.user_uuid, &conn).await else {
        audit_ticket_deny(&fill_agent, &ticket, "deny_item", &ip, &conn).await;
        return Err(denied("Item not available"));
    };
    let context = load_context(&fill_agent.user_uuid, &agent_token.uuid, std::slice::from_ref(&cipher), &conn).await;
    if !visible(&context, &cipher) || !agent_can_fill(true, is_reprompt(&cipher)) {
        audit_ticket_deny(&fill_agent, &ticket, "deny_item", &ip, &conn).await;
        return Err(denied("Item not available"));
    }
    let stored = stored_uris(&context, &cipher.uuid);
    if origin_allowed(stored, &ticket.origin, origin_policy()).is_err() {
        audit_ticket_deny(&fill_agent, &ticket, "deny_origin", &ip, &conn).await;
        return Err(denied("Origin not allowed"));
    }
    let Some(payload) = fill_payload_json(&FillPayloadInput {
        ticket_id: ticket.uuid.as_ref(),
        item_id: cipher.uuid.as_ref(),
        origin: &ticket.origin,
        cipher_key: cipher.key.as_deref(),
        data: &cipher.data,
        include_totp: CONFIG.agent_fill_include_totp(),
    }) else {
        audit_ticket_deny(&fill_agent, &ticket, "deny_item", &ip, &conn).await;
        return Err(denied("Item not available"));
    };
    audit(
        &fill_agent.user_uuid,
        Some(&agent_token.uuid),
        Some(&fill_agent.uuid),
        Some(&cipher.uuid),
        "redeem",
        Some(ticket.origin),
        "redeemed",
        &ip,
        &conn,
    )
    .await;
    Ok(Json(payload))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UriIndexBody {
    uris: Vec<UriIndexEntry>,
}

#[derive(Deserialize)]
struct UriIndexEntry {
    uri: String,
    #[serde(default, rename = "match", alias = "matchType")]
    match_type: Option<i32>,
}

#[put("/agent/items/<cipher_id>/uri-index", data = "<body>")]
async fn put_uri_index(
    cipher_id: CipherId,
    body: Json<UriIndexBody>,
    headers: Headers,
    ip: ClientIp,
    conn: DbConn,
) -> JsonResult {
    ensure_enabled()?;
    let Some(cipher) = find_personal_login(&cipher_id, &headers.user.uuid, &conn).await else {
        return Err(denied("Item not available"));
    };
    let entries: Vec<(String, Option<i32>)> =
        body.uris.iter().map(|entry| (entry.uri.clone(), entry.match_type)).collect();
    let prepared = crate::agent_fill::prepare_index_entries(&entries, CONFIG.agent_allow_regex_uri_match())
        .map_err(|_| denied("Invalid origin"))?;
    AgentCipherUri::replace(&cipher.uuid, &prepared, &conn).await?;
    let uris = public_origins(&prepared, CONFIG.agent_allow_ip_origins());
    audit(&headers.user.uuid, None, None, Some(&cipher.uuid), "uri_index", None, "updated", &ip, &conn).await;
    Ok(Json(json!({
        "object": "agentUriIndex",
        "id": cipher.uuid,
        "uris": uris,
    })))
}

#[delete("/agent/items/<cipher_id>/uri-index")]
async fn delete_uri_index(cipher_id: CipherId, headers: Headers, ip: ClientIp, conn: DbConn) -> JsonResult {
    ensure_enabled()?;
    let Some(cipher) = find_personal_login(&cipher_id, &headers.user.uuid, &conn).await else {
        return Err(denied("Item not available"));
    };
    AgentCipherUri::replace(&cipher.uuid, &[], &conn).await?;
    audit(&headers.user.uuid, None, None, Some(&cipher.uuid), "uri_index", None, "cleared", &ip, &conn).await;
    Ok(Json(json!({
        "object": "agentUriIndex",
        "id": cipher.uuid,
        "uris": [],
    })))
}
