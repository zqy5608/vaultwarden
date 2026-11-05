//! Pure rules for the fill-only Agent API.
//!
//! Handlers and database code call into this module so the secret boundary can be
//! tested without a database: AI responses are built by allowlist, and fill
//! redemption is a separate single-use transition.

mod policy;
mod token;
mod uri;

pub use policy::{
    AgentItemInput, FillPayloadInput, MAX_LIST, RedeemFacts, agent_can_fill, agent_can_see_item, evaluate_redeem,
    fill_agent_ticket_json, fill_payload_json, folder_picker_label, item_list_json, metadata_json, plaintext_username,
    query_matches, ticket_created_json, ticket_status, ticket_status_json,
};
pub use token::{
    ScopedCredentialKind, agent_api_gate, generate_scoped_token, is_scoped_agent_credential, scoped_credential_kind,
    token_hash, token_prefix_label,
};
pub use uri::{
    OriginDeny, OriginPolicy, StoredUri, normalize_origin, origin_allowed, plaintext_origins_from_login_data,
    prepare_index_entries, public_origins,
};
