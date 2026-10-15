CREATE TABLE IF NOT EXISTS realtime.applications (
  application_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
  rate_limits JSONB NOT NULL DEFAULT '{}'::jsonb,
  allowed_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS realtime_applications_tenant_idx
  ON realtime.applications(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS realtime.connections (
  connection_id UUID PRIMARY KEY,
  principal_id TEXT NOT NULL,
  application_id TEXT NULL,
  tenant_id TEXT NOT NULL,
  node_id TEXT NULL,
  connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  disconnected_at TIMESTAMPTZ NULL,
  status TEXT NOT NULL DEFAULT 'active',
  remote_address TEXT NULL,
  user_agent TEXT NULL,
  subscriptions JSONB NOT NULL DEFAULT '[]'::jsonb,
  bytes_in BIGINT NOT NULL DEFAULT 0,
  bytes_out BIGINT NOT NULL DEFAULT 0,
  messages_in BIGINT NOT NULL DEFAULT 0,
  messages_out BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS realtime_connections_tenant_status_idx
  ON realtime.connections(tenant_id, status, last_seen DESC);

CREATE INDEX IF NOT EXISTS realtime_connections_subscriptions_gin_idx
  ON realtime.connections USING GIN(subscriptions);

CREATE TABLE IF NOT EXISTS realtime.rooms (
  room_id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  channel TEXT NOT NULL UNIQUE REFERENCES realtime.channels(name) ON DELETE CASCADE,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS realtime_rooms_tenant_idx
  ON realtime.rooms(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS realtime.room_members (
  room_id UUID NOT NULL REFERENCES realtime.rooms(room_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(room_id, principal_id)
);
