CREATE TABLE agent_tokens (
    uuid         CHAR(36)    NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)    NOT NULL REFERENCES users (uuid),
    name         TEXT        NOT NULL,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(32) NOT NULL,
    created_at   TIMESTAMP   NOT NULL,
    revoked_at   TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX agent_tokens_user_idx ON agent_tokens (user_uuid);

CREATE TABLE agent_token_folders (
    agent_token_uuid CHAR(36) NOT NULL REFERENCES agent_tokens (uuid),
    folder_uuid      CHAR(36) NOT NULL REFERENCES folders (uuid),
    PRIMARY KEY (agent_token_uuid, folder_uuid)
);

CREATE TABLE fill_agents (
    uuid         CHAR(36)    NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)    NOT NULL REFERENCES users (uuid),
    name         TEXT        NOT NULL,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(32) NOT NULL,
    created_at   TIMESTAMP   NOT NULL,
    revoked_at   TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX fill_agents_user_idx ON fill_agents (user_uuid);

CREATE TABLE agent_cipher_uris (
    uuid        CHAR(36) NOT NULL PRIMARY KEY,
    cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid),
    uri         TEXT     NOT NULL,
    match_type  INTEGER
);

CREATE INDEX agent_cipher_uris_cipher_idx ON agent_cipher_uris (cipher_uuid);

CREATE TABLE fill_tickets (
    uuid             CHAR(36)     NOT NULL PRIMARY KEY,
    redeem_secret    VARCHAR(64)  NOT NULL,
    agent_token_uuid CHAR(36)     NOT NULL REFERENCES agent_tokens (uuid),
    fill_agent_uuid  CHAR(36)     NOT NULL REFERENCES fill_agents (uuid),
    user_uuid        CHAR(36)     NOT NULL REFERENCES users (uuid),
    cipher_uuid      CHAR(36)     NOT NULL REFERENCES ciphers (uuid),
    origin           VARCHAR(512) NOT NULL,
    created_at       TIMESTAMP    NOT NULL,
    expires_at       TIMESTAMP    NOT NULL,
    redeemed_at      TIMESTAMP
);

CREATE INDEX fill_tickets_fill_agent_idx ON fill_tickets (fill_agent_uuid);
CREATE INDEX fill_tickets_agent_token_idx ON fill_tickets (agent_token_uuid);

CREATE TABLE agent_audit_log (
    uuid             CHAR(36)     NOT NULL PRIMARY KEY,
    created_at       TIMESTAMP    NOT NULL,
    user_uuid        CHAR(36)     NOT NULL REFERENCES users (uuid),
    agent_token_uuid CHAR(36),
    fill_agent_uuid  CHAR(36),
    cipher_uuid      CHAR(36),
    action           VARCHAR(32)  NOT NULL,
    origin           VARCHAR(512),
    detail           VARCHAR(64)  NOT NULL,
    ip_address       VARCHAR(64)
);

CREATE INDEX agent_audit_log_created_idx ON agent_audit_log (created_at);
