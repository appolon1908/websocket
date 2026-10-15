CREATE TABLE IF NOT EXISTS realtime.channels (
  name TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  retention TEXT NOT NULL DEFAULT 'default',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS realtime.channel_sequences (
  channel TEXT PRIMARY KEY REFERENCES realtime.channels(name) ON DELETE CASCADE,
  last_sequence BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS realtime.events (
  id UUID PRIMARY KEY,
  channel TEXT NOT NULL REFERENCES realtime.channels(name) ON DELETE CASCADE,
  sequence BIGINT NOT NULL,
  type TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  correlation_id UUID NULL,
  causation_id UUID NULL,
  trace_id TEXT NULL,
  data JSONB NOT NULL,
  UNIQUE(channel, sequence)
);

CREATE INDEX IF NOT EXISTS realtime_events_channel_sequence_idx
  ON realtime.events(channel, sequence);

CREATE INDEX IF NOT EXISTS realtime_events_tenant_timestamp_idx
  ON realtime.events(tenant_id, timestamp DESC);
