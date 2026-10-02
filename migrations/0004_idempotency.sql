CREATE TABLE IF NOT EXISTS realtime.idempotency_records (
  tenant_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash CHAR(64) NOT NULL,
  state TEXT NOT NULL DEFAULT 'processing',
  response_status INTEGER NULL,
  response_body JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
  PRIMARY KEY(tenant_id, scope, idempotency_key)
);

CREATE INDEX IF NOT EXISTS realtime_idempotency_expiry_idx
  ON realtime.idempotency_records(expires_at);
