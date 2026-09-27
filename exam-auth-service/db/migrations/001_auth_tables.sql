-- Auth service tables. Additive only: nothing in the existing exam schema is changed.
-- Requires the base schema (users table, pgcrypto + citext extensions).

-- One row per signed-in device/browser ("session"). The refresh token is
-- "<session id>.<secret>"; only a SHA-256 hash of the secret is stored.
CREATE TABLE IF NOT EXISTS auth_sessions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    portal               VARCHAR(20) NOT NULL,                 -- 'admin' | 'exam'
    refresh_token_hash   CHAR(64)    NOT NULL,                 -- sha256 hex of current secret
    previous_token_hash  CHAR(64),                             -- last rotated secret (reuse detection)
    rotated_at           TIMESTAMPTZ,
    rotation_count       INTEGER     NOT NULL DEFAULT 0,
    user_agent           TEXT,
    ip_address           INET,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,                 -- idle expiry, pushed forward on refresh
    absolute_expires_at  TIMESTAMPTZ NOT NULL,                 -- hard limit
    revoked_at           TIMESTAMPTZ,
    revoked_reason       VARCHAR(40)
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_active
    ON auth_sessions (user_id, portal) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions (expires_at);

-- Login attempts, used for lockout (per account and per IP).
CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identifier   CITEXT      NOT NULL,                        -- normalised email or phone digits
    portal       VARCHAR(20) NOT NULL,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address   INET,
    succeeded    BOOLEAN     NOT NULL,
    reason       VARCHAR(40),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_identifier ON auth_login_attempts (identifier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip         ON auth_login_attempts (ip_address, created_at DESC);
