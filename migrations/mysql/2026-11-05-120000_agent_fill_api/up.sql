CREATE TABLE agent_tokens (
    uuid         CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)     NOT NULL,
    name         TEXT         NOT NULL,
    token_hash   VARCHAR(64)  NOT NULL,
    token_prefix VARCHAR(32)  NOT NULL,
    created_at   DATETIME     NOT NULL,
    revoked_at   DATETIME     NULL,
    last_used_at DATETIME     NULL,
    UNIQUE KEY agent_tokens_token_hash_idx (token_hash),
    INDEX agent_tokens_user_idx (user_uuid),
    CONSTRAINT fk_agent_tokens_user FOREIGN KEY (user_uuid) REFERENCES users (uuid)
);

CREATE TABLE agent_token_folders (
    agent_token_uuid CHAR(36) NOT NULL,
    folder_uuid      CHAR(36) NOT NULL,
    PRIMARY KEY (agent_token_uuid, folder_uuid),
    CONSTRAINT fk_agent_token_folders_token FOREIGN KEY (agent_token_uuid) REFERENCES agent_tokens (uuid),
    CONSTRAINT fk_agent_token_folders_folder FOREIGN KEY (folder_uuid) REFERENCES folders (uuid)
);

CREATE TABLE fill_agents (
    uuid         CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)     NOT NULL,
    name         TEXT         NOT NULL,
    token_hash   VARCHAR(64)  NOT NULL,
    token_prefix VARCHAR(32)  NOT NULL,
    created_at   DATETIME     NOT NULL,
    revoked_at   DATETIME     NULL,
    last_used_at DATETIME     NULL,
    UNIQUE KEY fill_agents_token_hash_idx (token_hash),
    INDEX fill_agents_user_idx (user_uuid),
    CONSTRAINT fk_fill_agents_user FOREIGN KEY (user_uuid) REFERENCES users (uuid)
);

CREATE TABLE agent_cipher_uris (
    uuid        CHAR(36) NOT NULL PRIMARY KEY,
    cipher_uuid CHAR(36) NOT NULL,
    uri         TEXT     NOT NULL,
    match_type  INTEGER  NULL,
    INDEX agent_cipher_uris_cipher_idx (cipher_uuid),
    CONSTRAINT fk_agent_cipher_uris_cipher FOREIGN KEY (cipher_uuid) REFERENCES ciphers (uuid)
);

CREATE TABLE fill_tickets (
    uuid             CHAR(36)    NOT NULL PRIMARY KEY,
    redeem_secret    VARCHAR(64) NOT NULL,
    agent_token_uuid CHAR(36)    NOT NULL,
    fill_agent_uuid  CHAR(36)    NOT NULL,
    user_uuid        CHAR(36)    NOT NULL,
    cipher_uuid      CHAR(36)    NOT NULL,
    origin           VARCHAR(512) NOT NULL,
    created_at       DATETIME    NOT NULL,
    expires_at       DATETIME    NOT NULL,
    redeemed_at      DATETIME    NULL,
    INDEX fill_tickets_fill_agent_idx (fill_agent_uuid),
    INDEX fill_tickets_agent_token_idx (agent_token_uuid),
    CONSTRAINT fk_fill_tickets_agent FOREIGN KEY (agent_token_uuid) REFERENCES agent_tokens (uuid),
    CONSTRAINT fk_fill_tickets_fill_agent FOREIGN KEY (fill_agent_uuid) REFERENCES fill_agents (uuid),
    CONSTRAINT fk_fill_tickets_user FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    CONSTRAINT fk_fill_tickets_cipher FOREIGN KEY (cipher_uuid) REFERENCES ciphers (uuid)
);

CREATE TABLE agent_audit_log (
    uuid             CHAR(36) NOT NULL PRIMARY KEY,
    created_at       DATETIME NOT NULL,
    user_uuid        CHAR(36) NOT NULL,
    agent_token_uuid CHAR(36) NULL,
    fill_agent_uuid  CHAR(36) NULL,
    cipher_uuid      CHAR(36) NULL,
    action           VARCHAR(32) NOT NULL,
    origin           VARCHAR(512) NULL,
    detail           VARCHAR(64) NOT NULL,
    ip_address       VARCHAR(64) NULL,
    INDEX agent_audit_log_created_idx (created_at),
    CONSTRAINT fk_agent_audit_log_user FOREIGN KEY (user_uuid) REFERENCES users (uuid)
);
