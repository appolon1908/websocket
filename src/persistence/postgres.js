import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;

function normalizeEvent(row) {
  if (!row) return null;
  return {
    id: row.id,
    sequence: Number(row.sequence),
    channel: row.channel,
    type: row.type,
    timestamp: new Date(row.timestamp).toISOString(),
    source: row.source,
    tenant_id: row.tenant_id,
    correlation_id: row.correlation_id || undefined,
    causation_id: row.causation_id || undefined,
    trace_id: row.trace_id || undefined,
    data: row.data,
  };
}

function normalizeApiKey(row, includeHash = false) {
  if (!row) return null;
  const value = {
    id: row.key_id,
    prefix: row.key_prefix,
    owner: row.owner,
    tenant_id: row.tenant_id,
    permissions: row.permissions || [],
    created_at: new Date(row.created_at).toISOString(),
    expires_at: row.expires_at ? new Date(row.expires_at).toISOString() : null,
    last_used_at: row.last_used_at ? new Date(row.last_used_at).toISOString() : null,
    revoked_at: row.revoked_at ? new Date(row.revoked_at).toISOString() : null,
  };
  if (includeHash) value.key_hash = row.key_hash;
  return value;
}

export class PostgresEventStore {
  constructor({ connectionString, max = 10, ssl = false } = {}) {
    if (!connectionString) throw new Error("REALTIME_DATABASE_URL required for postgres persistence");
    this.kind = "postgres";
    this.durable = true;
    this.pool = new Pool({ connectionString, max, ssl });
  }

  async init() {
    const result = await this.pool.query(
      `SELECT
        to_regclass('realtime.channels') AS channels,
        to_regclass('realtime.channel_sequences') AS channel_sequences,
        to_regclass('realtime.events') AS events,
        to_regclass('realtime.api_keys') AS api_keys`,
    );
    const state = result.rows[0] || {};
    if (!state.channels || !state.channel_sequences || !state.events || !state.api_keys) {
      throw new Error("database_migrations_required");
    }
  }

  async health() {
    try {
      await this.pool.query("SELECT 1");
      return { ok: true, kind: this.kind, durable: this.durable };
    } catch {
      return { ok: false, kind: this.kind, durable: this.durable };
    }
  }

  async createChannel({ name, tenantId, retention = "default" }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `INSERT INTO realtime.channels(name, tenant_id, retention)
         VALUES ($1, $2, $3)
         RETURNING name, tenant_id, retention, created_at`,
        [name, tenantId, retention],
      );
      await client.query(
        "INSERT INTO realtime.channel_sequences(channel, last_sequence) VALUES ($1, 0)",
        [name],
      );
      await client.query("COMMIT");
      const row = result.rows[0];
      return { ...row, created_at: new Date(row.created_at).toISOString() };
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") {
        const exists = new Error("channel_exists");
        exists.code = "channel_exists";
        throw exists;
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async listChannels() {
    const result = await this.pool.query(
      "SELECT name, tenant_id, retention, created_at FROM realtime.channels ORDER BY name ASC",
    );
    return result.rows.map(row => ({ ...row, created_at: new Date(row.created_at).toISOString() }));
  }

  async getChannel(name) {
    const result = await this.pool.query(
      "SELECT name, tenant_id, retention, created_at FROM realtime.channels WHERE name = $1",
      [name],
    );
    const row = result.rows[0];
    return row ? { ...row, created_at: new Date(row.created_at).toISOString() } : null;
  }

  async deleteChannel(name) {
    const result = await this.pool.query("DELETE FROM realtime.channels WHERE name = $1", [name]);
    return result.rowCount === 1;
  }

  async appendEvent({ channel, type, data, principal }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const owner = await client.query(
        "SELECT tenant_id FROM realtime.channels WHERE name = $1 FOR SHARE",
        [channel],
      );
      if (!owner.rowCount) {
        const missing = new Error("channel_not_found");
        missing.code = "channel_not_found";
        throw missing;
      }
      if (owner.rows[0].tenant_id !== principal.tenant_id && !channel.startsWith("public/")) {
        const forbidden = new Error("tenant_mismatch");
        forbidden.code = "tenant_mismatch";
        throw forbidden;
      }

      const sequenceResult = await client.query(
        `UPDATE realtime.channel_sequences
         SET last_sequence = last_sequence + 1
         WHERE channel = $1
         RETURNING last_sequence`,
        [channel],
      );
      if (!sequenceResult.rowCount) throw new Error("channel_sequence_missing");
      const sequence = Number(sequenceResult.rows[0].last_sequence);
      const id = crypto.randomUUID();

      const inserted = await client.query(
        `INSERT INTO realtime.events(
          id, channel, sequence, type, source, tenant_id,
          correlation_id, causation_id, trace_id, data
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING *`,
        [
          id,
          channel,
          sequence,
          type,
          principal.application_id || principal.sub,
          principal.tenant_id,
          data.correlation_id || null,
          data.causation_id || null,
          data.trace_id || null,
          JSON.stringify(data.data),
        ],
      );
      await client.query("COMMIT");
      return normalizeEvent(inserted.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getEvent(id) {
    const result = await this.pool.query("SELECT * FROM realtime.events WHERE id = $1", [id]);
    return normalizeEvent(result.rows[0]);
  }

  async listEvents(channel, { after = 0, before = null, limit = 100, type = null } = {}) {
    const values = [channel, after, limit];
    const clauses = ["channel = $1", "sequence > $2"];
    if (before !== null) {
      values.push(before);
      clauses.push(`sequence < $${values.length}`);
    }
    if (type) {
      values.push(type);
      clauses.push(`type = $${values.length}`);
    }
    const result = await this.pool.query(
      `SELECT * FROM realtime.events
       WHERE ${clauses.join(" AND ")}
       ORDER BY sequence ASC
       LIMIT $3`,
      values,
    );
    const items = result.rows.map(normalizeEvent);
    return {
      items,
      next_cursor: items.length === limit ? String(items.at(-1).sequence) : null,
    };
  }

  async createApiKey({
    id,
    hash,
    prefix,
    owner,
    tenantId,
    permissions,
    expiresAt = null,
  }) {
    const result = await this.pool.query(
      `INSERT INTO realtime.api_keys(
        key_id, key_hash, key_prefix, owner, tenant_id, permissions, expires_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *`,
      [id, hash, prefix, owner, tenantId, JSON.stringify(permissions), expiresAt],
    );
    return normalizeApiKey(result.rows[0]);
  }

  async listApiKeys(tenantId) {
    const result = await this.pool.query(
      `SELECT * FROM realtime.api_keys
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [tenantId],
    );
    return result.rows.map(row => normalizeApiKey(row));
  }

  async getApiKeyMetadata(id) {
    const result = await this.pool.query(
      "SELECT * FROM realtime.api_keys WHERE key_id = $1",
      [id],
    );
    return normalizeApiKey(result.rows[0]);
  }

  async getApiKeyAuthRecord(id) {
    const result = await this.pool.query(
      "SELECT * FROM realtime.api_keys WHERE key_id = $1",
      [id],
    );
    return normalizeApiKey(result.rows[0], true);
  }

  async revokeApiKey(id, tenantId) {
    const result = await this.pool.query(
      `UPDATE realtime.api_keys
       SET revoked_at = COALESCE(revoked_at, NOW())
       WHERE key_id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );
    return result.rowCount === 1;
  }

  async touchApiKey(id) {
    await this.pool.query(
      "UPDATE realtime.api_keys SET last_used_at = NOW() WHERE key_id = $1",
      [id],
    );
  }

  async close() {
    await this.pool.end();
  }
}
