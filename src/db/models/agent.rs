use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;

use crate::{
    agent_fill::{StoredUri, plaintext_origins_from_login_data},
    db::{
        DbConn,
        schema::{
            agent_audit_log, agent_cipher_uris, agent_token_folders, agent_tokens, ciphers, fill_agents, fill_tickets,
        },
    },
    error::MapResult,
    util::get_uuid,
};
use macros::UuidFromParam;

use super::{Cipher, CipherId, FolderId, UserId};

const LOGIN_ATYPE: i32 = 1;

/// `execute()` is `Result<usize, _>`, and `map_res` also has a `()` impl.
/// Pin the success type so a discarded `?` cannot make the call ambiguous.
fn db_exec(result: Result<usize, diesel::result::Error>, message: &'static str) -> Result<(), crate::Error> {
    result.map_res(message)
}

fn db_rows(result: Result<usize, diesel::result::Error>, message: &'static str) -> Result<usize, crate::Error> {
    result.map_res(message)
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = agent_tokens)]
#[diesel(primary_key(uuid))]
#[diesel(treat_none_as_null = true)]
pub struct AgentToken {
    pub uuid: AgentTokenId,
    pub user_uuid: UserId,
    pub name: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub created_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = fill_agents)]
#[diesel(primary_key(uuid))]
#[diesel(treat_none_as_null = true)]
pub struct FillAgent {
    pub uuid: FillAgentId,
    pub user_uuid: UserId,
    pub name: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub created_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub last_used_at: Option<NaiveDateTime>,
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = agent_token_folders)]
#[diesel(primary_key(agent_token_uuid, folder_uuid))]
pub struct AgentTokenFolder {
    pub agent_token_uuid: AgentTokenId,
    pub folder_uuid: FolderId,
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = agent_cipher_uris)]
#[diesel(primary_key(uuid))]
#[diesel(treat_none_as_null = true)]
pub struct AgentCipherUri {
    pub uuid: String,
    pub cipher_uuid: CipherId,
    pub uri: String,
    pub match_type: Option<i32>,
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = fill_tickets)]
#[diesel(primary_key(uuid))]
#[diesel(treat_none_as_null = true)]
pub struct FillTicket {
    pub uuid: FillTicketId,
    pub redeem_secret: String,
    pub agent_token_uuid: AgentTokenId,
    pub fill_agent_uuid: FillAgentId,
    pub user_uuid: UserId,
    pub cipher_uuid: CipherId,
    pub origin: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub redeemed_at: Option<NaiveDateTime>,
}

#[derive(Clone, Identifiable, Queryable, Insertable)]
#[diesel(table_name = agent_audit_log)]
#[diesel(primary_key(uuid))]
#[diesel(treat_none_as_null = true)]
pub struct AgentAudit {
    pub uuid: String,
    pub created_at: NaiveDateTime,
    pub user_uuid: UserId,
    pub agent_token_uuid: Option<AgentTokenId>,
    pub fill_agent_uuid: Option<FillAgentId>,
    pub cipher_uuid: Option<CipherId>,
    pub action: String,
    pub origin: Option<String>,
    pub detail: String,
    pub ip_address: Option<String>,
}

impl AgentToken {
    pub async fn create(
        user_uuid: UserId,
        name: String,
        token_hash: String,
        token_prefix: String,
        conn: &DbConn,
    ) -> Result<Self, crate::Error> {
        let row = Self {
            uuid: AgentTokenId(get_uuid()),
            user_uuid,
            name,
            token_hash,
            token_prefix,
            created_at: Utc::now().naive_utc(),
            revoked_at: None,
            last_used_at: None,
        };
        let inserted = row.clone();
        conn.run(move |conn| {
            db_exec(
                diesel::insert_into(agent_tokens::table).values(&inserted).execute(conn),
                "Error saving agent token",
            )
        })
        .await?;
        Ok(row)
    }

    pub async fn find_by_uuid(uuid: &AgentTokenId, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.clone();
        conn.run(move |conn| agent_tokens::table.filter(agent_tokens::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_active_by_hash(token_hash: &str, conn: &DbConn) -> Option<Self> {
        let token_hash = token_hash.to_owned();
        conn.run(move |conn| {
            agent_tokens::table
                .filter(agent_tokens::token_hash.eq(token_hash))
                .filter(agent_tokens::revoked_at.is_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn list_all(conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            agent_tokens::table
                .order_by(agent_tokens::created_at.desc())
                .load::<Self>(conn)
                .expect("Error loading agent tokens")
        })
        .await
    }

    pub async fn ids_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<AgentTokenId> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            agent_tokens::table
                .filter(agent_tokens::user_uuid.eq(user_uuid))
                .select(agent_tokens::uuid)
                .load::<AgentTokenId>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn touch(&self, conn: &DbConn) {
        let uuid = self.uuid.clone();
        let now = Utc::now().naive_utc();
        drop(
            conn.run(move |conn| {
                diesel::update(agent_tokens::table.filter(agent_tokens::uuid.eq(uuid)))
                    .set(agent_tokens::last_used_at.eq(now))
                    .execute(conn)
            })
            .await,
        );
    }

    pub async fn revoke(&self, conn: &DbConn) -> Result<(), crate::Error> {
        let uuid = self.uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(agent_tokens::table.filter(agent_tokens::uuid.eq(uuid)))
                .set(agent_tokens::revoked_at.eq(now))
                .execute(conn)
                .map_res("Error revoking agent token")
        })
        .await
    }

    pub async fn delete_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(agent_tokens::table.filter(agent_tokens::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting agent tokens")
        })
        .await
    }
}

impl FillAgent {
    pub async fn create(
        user_uuid: UserId,
        name: String,
        token_hash: String,
        token_prefix: String,
        conn: &DbConn,
    ) -> Result<Self, crate::Error> {
        let row = Self {
            uuid: FillAgentId(get_uuid()),
            user_uuid,
            name,
            token_hash,
            token_prefix,
            created_at: Utc::now().naive_utc(),
            revoked_at: None,
            last_used_at: None,
        };
        let inserted = row.clone();
        conn.run(move |conn| {
            db_exec(diesel::insert_into(fill_agents::table).values(&inserted).execute(conn), "Error saving fill agent")
        })
        .await?;
        Ok(row)
    }

    pub async fn find_by_uuid(uuid: &FillAgentId, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.clone();
        conn.run(move |conn| fill_agents::table.filter(fill_agents::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_active_by_hash(token_hash: &str, conn: &DbConn) -> Option<Self> {
        let token_hash = token_hash.to_owned();
        conn.run(move |conn| {
            fill_agents::table
                .filter(fill_agents::token_hash.eq(token_hash))
                .filter(fill_agents::revoked_at.is_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_active_by_id(uuid: &FillAgentId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.clone();
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            fill_agents::table
                .filter(fill_agents::uuid.eq(uuid))
                .filter(fill_agents::user_uuid.eq(user_uuid))
                .filter(fill_agents::revoked_at.is_null())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn list_all(conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            fill_agents::table
                .order_by(fill_agents::created_at.desc())
                .load::<Self>(conn)
                .expect("Error loading fill agents")
        })
        .await
    }

    pub async fn touch(&self, conn: &DbConn) {
        let uuid = self.uuid.clone();
        let now = Utc::now().naive_utc();
        drop(
            conn.run(move |conn| {
                diesel::update(fill_agents::table.filter(fill_agents::uuid.eq(uuid)))
                    .set(fill_agents::last_used_at.eq(now))
                    .execute(conn)
            })
            .await,
        );
    }

    pub async fn revoke(&self, conn: &DbConn) -> Result<(), crate::Error> {
        let uuid = self.uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(fill_agents::table.filter(fill_agents::uuid.eq(uuid)))
                .set(fill_agents::revoked_at.eq(now))
                .execute(conn)
                .map_res("Error revoking fill agent")
        })
        .await
    }

    pub async fn delete_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(fill_agents::table.filter(fill_agents::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting fill agents")
        })
        .await
    }
}

impl AgentTokenFolder {
    pub async fn replace(token_uuid: &AgentTokenId, folders: &[FolderId], conn: &DbConn) -> Result<(), crate::Error> {
        let token_uuid = token_uuid.clone();
        let folders = folders.to_vec();
        conn.run(move |conn| {
            db_exec(
                diesel::delete(
                    agent_token_folders::table.filter(agent_token_folders::agent_token_uuid.eq(&token_uuid)),
                )
                .execute(conn),
                "Error clearing agent folder ACL",
            )?;
            for folder_uuid in folders {
                db_exec(
                    diesel::insert_into(agent_token_folders::table)
                        .values(&AgentTokenFolder {
                            agent_token_uuid: token_uuid.clone(),
                            folder_uuid,
                        })
                        .execute(conn),
                    "Error saving agent folder ACL",
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn folders_for_token(token_uuid: &AgentTokenId, conn: &DbConn) -> Vec<FolderId> {
        let token_uuid = token_uuid.clone();
        conn.run(move |conn| {
            agent_token_folders::table
                .filter(agent_token_folders::agent_token_uuid.eq(token_uuid))
                .select(agent_token_folders::folder_uuid)
                .load::<FolderId>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn delete_by_tokens(token_ids: &[AgentTokenId], conn: &DbConn) -> Result<(), crate::Error> {
        if token_ids.is_empty() {
            return Ok(());
        }
        let token_ids = token_ids.to_vec();
        conn.run(move |conn| {
            diesel::delete(agent_token_folders::table.filter(agent_token_folders::agent_token_uuid.eq_any(token_ids)))
                .execute(conn)
                .map_res("Error deleting agent folder ACL")
        })
        .await
    }

    pub async fn delete_by_folder(folder_uuid: &FolderId, conn: &DbConn) -> Result<(), crate::Error> {
        let folder_uuid = folder_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(agent_token_folders::table.filter(agent_token_folders::folder_uuid.eq(folder_uuid)))
                .execute(conn)
                .map_res("Error deleting agent folder ACL")
        })
        .await
    }
}

impl AgentCipherUri {
    pub async fn replace(cipher_uuid: &CipherId, uris: &[StoredUri], conn: &DbConn) -> Result<(), crate::Error> {
        Self::delete_by_cipher(cipher_uuid, conn).await?;
        for uri in uris {
            let row = Self {
                uuid: get_uuid(),
                cipher_uuid: cipher_uuid.clone(),
                uri: uri.uri.clone(),
                match_type: uri.match_type,
            };
            conn.run(move |conn| {
                db_exec(
                    diesel::insert_into(agent_cipher_uris::table).values(&row).execute(conn),
                    "Error saving agent URI index",
                )
            })
            .await?;
        }
        Ok(())
    }

    pub async fn find_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Vec<StoredUri> {
        let cipher_uuid = cipher_uuid.clone();
        conn.run(move |conn| {
            agent_cipher_uris::table
                .filter(agent_cipher_uris::cipher_uuid.eq(cipher_uuid))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
        .into_iter()
        .map(|row| StoredUri {
            uri: row.uri,
            match_type: row.match_type,
        })
        .collect()
    }

    pub async fn find_for_ciphers(cipher_ids: &[CipherId], conn: &DbConn) -> Vec<(CipherId, StoredUri)> {
        if cipher_ids.is_empty() {
            return Vec::new();
        }
        let cipher_ids = cipher_ids.to_vec();
        conn.run(move |conn| {
            agent_cipher_uris::table
                .filter(agent_cipher_uris::cipher_uuid.eq_any(cipher_ids))
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
        .into_iter()
        .map(|row| {
            (
                row.cipher_uuid,
                StoredUri {
                    uri: row.uri,
                    match_type: row.match_type,
                },
            )
        })
        .collect()
    }

    pub async fn delete_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Result<(), crate::Error> {
        let cipher_uuid = cipher_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(agent_cipher_uris::table.filter(agent_cipher_uris::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error deleting agent URI index")
        })
        .await
    }
}

impl FillTicket {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        redeem_secret: String,
        agent_token_uuid: AgentTokenId,
        fill_agent_uuid: FillAgentId,
        user_uuid: UserId,
        cipher_uuid: CipherId,
        origin: String,
        expires_at: NaiveDateTime,
        conn: &DbConn,
    ) -> Result<Self, crate::Error> {
        let row = Self {
            uuid: FillTicketId(get_uuid()),
            redeem_secret,
            agent_token_uuid,
            fill_agent_uuid,
            user_uuid,
            cipher_uuid,
            origin,
            created_at: Utc::now().naive_utc(),
            expires_at,
            redeemed_at: None,
        };
        let inserted = row.clone();
        conn.run(move |conn| {
            db_exec(
                diesel::insert_into(fill_tickets::table).values(&inserted).execute(conn),
                "Error saving fill ticket",
            )
        })
        .await?;
        Ok(row)
    }

    pub async fn find_by_uuid(uuid: &FillTicketId, conn: &DbConn) -> Option<Self> {
        let uuid = uuid.clone();
        conn.run(move |conn| fill_tickets::table.filter(fill_tickets::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn list_pending_for_fill_agent(fill_agent_uuid: &FillAgentId, conn: &DbConn) -> Vec<Self> {
        let fill_agent_uuid = fill_agent_uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            fill_tickets::table
                .filter(fill_tickets::fill_agent_uuid.eq(fill_agent_uuid))
                .filter(fill_tickets::redeemed_at.is_null())
                .filter(fill_tickets::expires_at.gt(now))
                .filter(fill_tickets::redeem_secret.ne(""))
                .order_by(fill_tickets::created_at.asc())
                .limit(20)
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    /// Single-use claim. Clears `redeem_secret` in the same update that marks the ticket redeemed.
    pub async fn claim_redeem(uuid: &FillTicketId, conn: &DbConn) -> Result<bool, crate::Error> {
        let uuid = uuid.clone();
        let now = Utc::now().naive_utc();
        let updated = db_rows(
            conn.run(move |conn| {
                diesel::update(fill_tickets::table)
                    .filter(fill_tickets::uuid.eq(uuid))
                    .filter(fill_tickets::redeemed_at.is_null())
                    .filter(fill_tickets::expires_at.gt(now))
                    .filter(fill_tickets::redeem_secret.ne(""))
                    .set((fill_tickets::redeemed_at.eq(now), fill_tickets::redeem_secret.eq("")))
                    .execute(conn)
            })
            .await,
            "Error redeeming fill ticket",
        )?;
        Ok(updated == 1)
    }

    pub async fn delete_by_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Result<(), crate::Error> {
        let cipher_uuid = cipher_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(fill_tickets::table.filter(fill_tickets::cipher_uuid.eq(cipher_uuid)))
                .execute(conn)
                .map_res("Error deleting fill tickets")
        })
        .await
    }

    pub async fn delete_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(fill_tickets::table.filter(fill_tickets::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting fill tickets")
        })
        .await
    }
}

impl AgentAudit {
    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        user_uuid: UserId,
        agent_token_uuid: Option<AgentTokenId>,
        fill_agent_uuid: Option<FillAgentId>,
        cipher_uuid: Option<CipherId>,
        action: &'static str,
        origin: Option<String>,
        detail: &'static str,
        ip_address: Option<String>,
        conn: &DbConn,
    ) {
        let row = Self {
            uuid: get_uuid(),
            created_at: Utc::now().naive_utc(),
            user_uuid,
            agent_token_uuid,
            fill_agent_uuid,
            cipher_uuid,
            action: action.to_owned(),
            origin,
            detail: detail.to_owned(),
            ip_address,
        };
        if let Err(err) = conn
            .run(move |conn| {
                db_exec(
                    diesel::insert_into(agent_audit_log::table).values(&row).execute(conn),
                    "Error saving agent audit",
                )
            })
            .await
        {
            error!("Agent audit write failed: {err}");
        }
    }

    pub async fn recent(conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            agent_audit_log::table
                .order_by(agent_audit_log::created_at.desc())
                .limit(100)
                .load::<Self>(conn)
                .unwrap_or_default()
        })
        .await
    }

    pub async fn delete_by_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
        let user_uuid = user_uuid.clone();
        conn.run(move |conn| {
            diesel::delete(agent_audit_log::table.filter(agent_audit_log::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting agent audit")
        })
        .await
    }
}

pub async fn find_personal_logins(user_uuid: &UserId, conn: &DbConn) -> Vec<Cipher> {
    let user_uuid = user_uuid.clone();
    conn.run(move |conn| {
        ciphers::table
            .filter(ciphers::user_uuid.eq(user_uuid))
            .filter(ciphers::organization_uuid.is_null())
            .filter(ciphers::deleted_at.is_null())
            .filter(ciphers::atype.eq(LOGIN_ATYPE))
            .load::<Cipher>(conn)
            .unwrap_or_default()
    })
    .await
}

pub async fn find_personal_login(cipher_uuid: &CipherId, user_uuid: &UserId, conn: &DbConn) -> Option<Cipher> {
    let cipher_uuid = cipher_uuid.clone();
    let user_uuid = user_uuid.clone();
    conn.run(move |conn| {
        ciphers::table
            .filter(ciphers::uuid.eq(cipher_uuid))
            .filter(ciphers::user_uuid.eq(user_uuid))
            .filter(ciphers::organization_uuid.is_null())
            .filter(ciphers::deleted_at.is_null())
            .filter(ciphers::atype.eq(LOGIN_ATYPE))
            .first::<Cipher>(conn)
            .ok()
    })
    .await
}

pub async fn sync_cipher_uri_index(
    cipher_uuid: &CipherId,
    atype: i32,
    data: &str,
    conn: &DbConn,
) -> Result<(), crate::Error> {
    if atype != LOGIN_ATYPE {
        return AgentCipherUri::delete_by_cipher(cipher_uuid, conn).await;
    }
    let indexed = plaintext_origins_from_login_data(data);
    if indexed.is_empty() {
        // Leave a manually published index in place. Encrypted vault URIs are not visible here.
        return Ok(());
    }
    AgentCipherUri::replace(cipher_uuid, &indexed, conn).await
}

pub async fn purge_cipher(cipher_uuid: &CipherId, conn: &DbConn) -> Result<(), crate::Error> {
    AgentCipherUri::delete_by_cipher(cipher_uuid, conn).await?;
    FillTicket::delete_by_cipher(cipher_uuid, conn).await
}

pub async fn delete_all_for_user(user_uuid: &UserId, conn: &DbConn) -> Result<(), crate::Error> {
    FillTicket::delete_by_user(user_uuid, conn).await?;
    let token_ids = AgentToken::ids_by_user(user_uuid, conn).await;
    AgentTokenFolder::delete_by_tokens(&token_ids, conn).await?;
    AgentToken::delete_by_user(user_uuid, conn).await?;
    FillAgent::delete_by_user(user_uuid, conn).await?;
    AgentAudit::delete_by_user(user_uuid, conn).await
}

pub async fn delete_folder_acl(folder_uuid: &FolderId, conn: &DbConn) -> Result<(), crate::Error> {
    AgentTokenFolder::delete_by_folder(folder_uuid, conn).await
}

#[derive(
    Clone, Debug, AsRef, Deref, DieselNewType, Display, From, Hash, PartialEq, Eq, Serialize, Deserialize, UuidFromParam,
)]
pub struct AgentTokenId(String);

#[derive(
    Clone, Debug, AsRef, Deref, DieselNewType, Display, From, Hash, PartialEq, Eq, Serialize, Deserialize, UuidFromParam,
)]
pub struct FillAgentId(String);

#[derive(
    Clone, Debug, AsRef, Deref, DieselNewType, Display, From, Hash, PartialEq, Eq, Serialize, Deserialize, UuidFromParam,
)]
pub struct FillTicketId(String);
