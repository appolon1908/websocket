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
        to_regclass('realtime.api_keys') AS api_keys,
        to_regclass('realtime.applications') AS applications,
        to_regclass('realtime.connections') AS connections,
        to_regclass('realtime.rooms') AS rooms,
        to_regclass('realtime.room_members') AS room_members,
        to_regclass('realtime.idempotency_records') AS idempotency_records`,
    );
    const state = result.rows[0] || {};
    if (
      !state.channels ||
      !state.channel_sequences ||
      !state.events ||
      !state.api_keys ||
      !state.applications ||
      !state.connections ||
      !state.rooms ||
      !state.room_members ||
      !state.idempotency_records
    ) {
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

  async createApplication({
    applicationId,
    name,
    tenantId,
    permissions = [],
    rateLimits = {},
    allowedOrigins = [],
  }) {
    const result = await this.pool.query(
      `INSERT INTO realtime.applications(
        application_id, name, tenant_id, permissions, rate_limits, allowed_origins
      ) VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING *`,
      [
        applicationId,
        name,
        tenantId,
        JSON.stringify(permissions),
        JSON.stringify(rateLimits),
        JSON.stringify(allowedOrigins),
      ],
    );
    return this.#application(result.rows[0]);
  }

  async listApplications(tenantId) {
    const result = await this.pool.query(
      `SELECT * FROM realtime.applications
       WHERE tenant_id = $1 ORDER BY created_at DESC`,
      [tenantId],
    );
    return result.rows.map(row => this.#application(row));
  }

  async getApplication(applicationId, tenantId) {
    const result = await this.pool.query(
      `SELECT * FROM realtime.applications
       WHERE application_id = $1 AND tenant_id = $2`,
      [applicationId, tenantId],
    );
    return this.#application(result.rows[0]);
  }

  #application(row) {
    if (!row) return null;
    return {
      application_id: row.application_id,
      name: row.name,
      tenant_id: row.tenant_id,
      status: row.status,
      permissions: row.permissions || [],
      rate_limits: row.rate_limits || {},
      allowed_origins: row.allowed_origins || [],
      created_at: new Date(row.created_at).toISOString(),
    };
  }

  async openConnection({
    connectionId,
    principalId,
    applicationId,
    tenantId,
    nodeId = null,
    remoteAddress = null,
    userAgent = null,
  }) {
    const result = await this.pool.query(
      `INSERT INTO realtime.connections(
        connection_id, principal_id, application_id, tenant_id,
        node_id, remote_address, user_agent
      ) VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *`,
      [
        connectionId,
        principalId,
        applicationId,
        tenantId,
        nodeId,
        remoteAddress,
        userAgent,
      ],
    );
    return this.#connection(result.rows[0]);
  }

  async updateConnection(connectionId, {
    subscriptions,
    bytesIn = 0,
    bytesOut = 0,
    messagesIn = 0,
    messagesOut = 0,
  } = {}) {
    const result = await this.pool.query(
      `UPDATE realtime.connections
       SET last_seen = NOW(),
           subscriptions = COALESCE($2::jsonb, subscriptions),
           bytes_in = bytes_in + $3,
           bytes_out = bytes_out + $4,
           messages_in = messages_in + $5,
           messages_out = messages_out + $6
       WHERE connection_id = $1
       RETURNING *`,
      [
        connectionId,
        subscriptions ? JSON.stringify(subscriptions) : null,
        bytesIn,
        bytesOut,
        messagesIn,
        messagesOut,
      ],
    );
    return this.#connection(result.rows[0]);
  }

  async closeConnection(connectionId) {
    const result = await this.pool.query(
      `UPDATE realtime.connections
       SET status = 'closed',
           disconnected_at = COALESCE(disconnected_at, NOW()),
           last_seen = NOW()
       WHERE connection_id = $1
       RETURNING connection_id`,
      [connectionId],
    );
    return result.rowCount === 1;
  }

  async listConnections(tenantId, { activeOnly = false } = {}) {
    const result = await this.pool.query(
      `SELECT * FROM realtime.connections
       WHERE tenant_id = $1
         AND ($2::boolean = false OR status = 'active')
       ORDER BY connected_at DESC`,
      [tenantId, activeOnly],
    );
    return result.rows.map(row => this.#connection(row));
  }

  async getConnection(connectionId, tenantId) {
    const result = await this.pool.query(
      `SELECT * FROM realtime.connections
       WHERE connection_id = $1 AND tenant_id = $2`,
      [connectionId, tenantId],
    );
    return this.#connection(result.rows[0]);
  }

  async listPresence(channel, tenantId) {
    const result = await this.pool.query(
      `SELECT connection_id, principal_id, application_id, connected_at, last_seen
       FROM realtime.connections
       WHERE tenant_id = $1
         AND status = 'active'
         AND subscriptions ? $2
       ORDER BY connected_at ASC`,
      [tenantId, channel],
    );
    return result.rows.map(row => ({
      connection_id: row.connection_id,
      principal_id: row.principal_id,
      application_id: row.application_id,
      connected_at: new Date(row.connected_at).toISOString(),
      last_seen: new Date(row.last_seen).toISOString(),
    }));
  }

  #connection(row) {
    if (!row) return null;
    return {
      connection_id: row.connection_id,
      principal_id: row.principal_id,
      application_id: row.application_id,
      tenant_id: row.tenant_id,
      node_id: row.node_id,
      connected_at: new Date(row.connected_at).toISOString(),
      last_seen: new Date(row.last_seen).toISOString(),
      disconnected_at: row.disconnected_at
        ? new Date(row.disconnected_at).toISOString()
        : null,
      status: row.status,
      remote_address: row.remote_address,
      user_agent: row.user_agent,
      subscriptions: row.subscriptions || [],
      bytes_in: Number(row.bytes_in || 0),
      bytes_out: Number(row.bytes_out || 0),
      messages_in: Number(row.messages_in || 0),
      messages_out: Number(row.messages_out || 0),
    };
  }

  async createRoom({ roomId, tenantId, name, type, createdBy, channel }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO realtime.channels(name, tenant_id, retention)
         VALUES ($1, $2, '24h')`,
        [channel, tenantId],
      );
      await client.query(
        "INSERT INTO realtime.channel_sequences(channel, last_sequence) VALUES ($1, 0)",
        [channel],
      );
      const result = await client.query(
        `INSERT INTO realtime.rooms(
          room_id, tenant_id, name, type, channel, created_by
        ) VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING *`,
        [roomId, tenantId, name, type, channel, createdBy],
      );
      await client.query("COMMIT");
      return this.#room(result.rows[0], []);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getRoom(roomId, tenantId) {
    const result = await this.pool.query(
      `SELECT r.*,
        COALESCE(
          jsonb_agg(m.principal_id) FILTER (WHERE m.principal_id IS NOT NULL),
          '[]'::jsonb
        ) AS members
       FROM realtime.rooms r
       LEFT JOIN realtime.room_members m ON m.room_id = r.room_id
       WHERE r.room_id = $1 AND r.tenant_id = $2
       GROUP BY r.room_id`,
      [roomId, tenantId],
    );
    return this.#room(result.rows[0], result.rows[0]?.members || []);
  }

  async deleteRoom(roomId, tenantId) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        "SELECT channel FROM realtime.rooms WHERE room_id = $1 AND tenant_id = $2 FOR UPDATE",
        [roomId, tenantId],
      );
      if (!existing.rowCount) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query("DELETE FROM realtime.rooms WHERE room_id = $1", [roomId]);
      await client.query("DELETE FROM realtime.channels WHERE name = $1", [
        existing.rows[0].channel,
      ]);
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async joinRoom(roomId, tenantId, principalId) {
    const room = await this.getRoom(roomId, tenantId);
    if (!room) return null;
    await this.pool.query(
      `INSERT INTO realtime.room_members(room_id, principal_id)
       VALUES ($1,$2)
       ON CONFLICT (room_id, principal_id) DO NOTHING`,
      [roomId, principalId],
    );
    return this.getRoom(roomId, tenantId);
  }

  async leaveRoom(roomId, tenantId, principalId) {
    const room = await this.getRoom(roomId, tenantId);
    if (!room) return null;
    await this.pool.query(
      "DELETE FROM realtime.room_members WHERE room_id = $1 AND principal_id = $2",
      [roomId, principalId],
    );
    return this.getRoom(roomId, tenantId);
  }

  #room(row, members = []) {
    if (!row) return null;
    return {
      room_id: row.room_id,
      tenant_id: row.tenant_id,
      name: row.name,
      type: row.type,
      channel: row.channel,
      created_by: row.created_by,
      created_at: new Date(row.created_at).toISOString(),
      members: Array.isArray(members) ? members : [],
    };
  }

  async claimIdempotency({ tenantId, scope, key, requestHash }) {
    const inserted = await this.pool.query(
      `INSERT INTO realtime.idempotency_records(
        tenant_id, scope, idempotency_key, request_hash
      ) VALUES ($1,$2,$3,$4)
      ON CONFLICT (tenant_id, scope, idempotency_key) DO NOTHING
      RETURNING state`,
      [tenantId, scope, key, requestHash],
    );
    if (inserted.rowCount === 1) return { state: "claimed" };

    const existing = await this.pool.query(
      `SELECT request_hash, state, response_status, response_body
       FROM realtime.idempotency_records
       WHERE tenant_id = $1 AND scope = $2 AND idempotency_key = $3`,
      [tenantId, scope, key],
    );
    const row = existing.rows[0];
    if (!row) return { state: "processing" };
    if (row.request_hash !== requestHash) return { state: "conflict" };
    if (row.state === "completed") {
      return {
        state: "replay",
        response_status: row.response_status,
        response_body: row.response_body,
      };
    }
    return { state: "processing" };
  }

  async completeIdempotency({ tenantId, scope, key, responseStatus, responseBody }) {
    const result = await this.pool.query(
      `UPDATE realtime.idempotency_records
       SET state = 'completed',
           response_status = $4,
           response_body = $5,
           completed_at = NOW()
       WHERE tenant_id = $1 AND scope = $2 AND idempotency_key = $3
       RETURNING idempotency_key`,
      [tenantId, scope, key, responseStatus, JSON.stringify(responseBody)],
    );
    return result.rowCount === 1;
  }

  async releaseIdempotency({ tenantId, scope, key }) {
    const result = await this.pool.query(
      `DELETE FROM realtime.idempotency_records
       WHERE tenant_id = $1 AND scope = $2 AND idempotency_key = $3
         AND state = 'processing'`,
      [tenantId, scope, key],
    );
    return result.rowCount === 1;
  }

  async close() {
    await this.pool.end();
  }
}
