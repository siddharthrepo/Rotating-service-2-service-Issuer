CREATE TABLE services (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name                VARCHAR(128)    NOT NULL,
    client_id           CHAR(26) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    client_secret_hash  VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    owner_team          VARCHAR(128)    NULL,
    description         VARCHAR(512)    NULL,
    status              ENUM('active','disabled') NOT NULL DEFAULT 'active',
    secret_rotated_at   TIMESTAMP       NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_services_name      (name),
    UNIQUE KEY uk_services_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE grants (
    id                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    caller_service_id     BIGINT UNSIGNED NOT NULL,
    target_service_id     BIGINT UNSIGNED NOT NULL,
    scopes                JSON            NOT NULL,
    lifetime_seconds      INT UNSIGNED    NOT NULL DEFAULT 2700,
    rotate_after_seconds  INT UNSIGNED    NOT NULL DEFAULT 900,
    status                ENUM('active','revoked') NOT NULL DEFAULT 'active',
    revoked_at            TIMESTAMP       NULL,
    revoked_reason        VARCHAR(512)    NULL,
    created_at            TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                          ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_grants_pair (caller_service_id, target_service_id),
    KEY idx_grants_target (target_service_id),
    CONSTRAINT fk_grants_caller FOREIGN KEY (caller_service_id) REFERENCES services(id),
    CONSTRAINT fk_grants_target FOREIGN KEY (target_service_id) REFERENCES services(id),
    CONSTRAINT ck_grants_rotate CHECK (rotate_after_seconds < lifetime_seconds),
    CONSTRAINT ck_grants_noself CHECK (caller_service_id <> target_service_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE tokens (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    jti           CHAR(26) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    grant_id      BIGINT UNSIGNED NOT NULL,
    token_hash    CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    issued_at     TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at    TIMESTAMP(3)    NOT NULL,
    revoked_at    TIMESTAMP(3)    NULL,
    superseded_at TIMESTAMP(3)    NULL,
    issued_to_ip  VARBINARY(16)   NULL,

    current_grant_id BIGINT UNSIGNED GENERATED ALWAYS AS
        (IF(superseded_at IS NULL AND revoked_at IS NULL, grant_id, NULL)) VIRTUAL,

    UNIQUE KEY uk_tokens_hash    (token_hash),
    UNIQUE KEY uk_tokens_jti     (jti),
    UNIQUE KEY uk_tokens_current (current_grant_id),
    KEY idx_tokens_grant_live (grant_id, expires_at),
    KEY idx_tokens_expiry     (expires_at),
    CONSTRAINT fk_tokens_grant FOREIGN KEY (grant_id) REFERENCES grants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    actor_type  ENUM('service','user','system') NOT NULL,
    actor_id    VARCHAR(128)    NOT NULL,
    action      VARCHAR(64)     NOT NULL,
    target_type VARCHAR(64)     NULL,
    target_id   VARCHAR(128)    NULL,
    reason      VARCHAR(512)    NULL,
    metadata    JSON            NULL,
    request_ip  VARBINARY(16)   NULL,
    created_at  TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_audit_created (created_at),
    KEY idx_audit_actor   (actor_id, created_at),
    KEY idx_audit_target  (target_type, target_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE grant_stats (
    grant_id     BIGINT UNSIGNED NOT NULL,
    bucket_start TIMESTAMP       NOT NULL,
    call_count   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    deny_count   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (grant_id, bucket_start),
    KEY idx_stats_bucket (bucket_start),
    CONSTRAINT fk_stats_grant FOREIGN KEY (grant_id) REFERENCES grants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE users (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255)    NOT NULL,
    name          VARCHAR(128)    NOT NULL,
    password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    role          ENUM('admin','operator','viewer') NOT NULL DEFAULT 'viewer',
    status        ENUM('active','disabled') NOT NULL DEFAULT 'active',
    created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
    id         CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    user_id    BIGINT UNSIGNED NOT NULL,
    expires_at TIMESTAMP       NOT NULL,
    created_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
