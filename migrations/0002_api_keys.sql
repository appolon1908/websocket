CREATE TABLE IF NOT EXISTS realtime.api_keys (
  key_id TEXT PRIMARY KEY,
  key_hash CHAR(64) NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NULL,
  last_used_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS realtime_api_keys_tenant_active_idx
  ON realtime.api_keys(tenant_id, revoked_at, expires_at);
