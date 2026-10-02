import crypto from "node:crypto";

const apiKeyMetadata = record => ({
  id: record.id,
  prefix: record.prefix,
  owner: record.owner,
  tenant_id: record.tenant_id,
  permissions: [...record.permissions],
  created_at: record.created_at,
  expires_at: record.expires_at,
  last_used_at: record.last_used_at,
  revoked_at: record.revoked_at,
});

const cloneApplication = record => ({
  application_id: record.application_id,
  name: record.name,
  tenant_id: record.tenant_id,
  status: record.status,
  permissions: [...record.permissions],
  rate_limits: { ...record.rate_limits },
  allowed_origins: [...record.allowed_origins],
  created_at: record.created_at,
});

const cloneConnection = record => ({
  connection_id: record.connection_id,
  principal_id: record.principal_id,
  application_id: record.application_id,
  tenant_id: record.tenant_id,
  node_id: record.node_id,
  connected_at: record.connected_at,
  last_seen: record.last_seen,
  disconnected_at: record.disconnected_at,
  status: record.status,
  remote_address: record.remote_address,
  user_agent: record.user_agent,
  subscriptions: [...record.subscriptions],
  bytes_in: record.bytes_in,
  bytes_out: record.bytes_out,
  messages_in: record.messages_in,
  messages_out: record.messages_out,
});

const cloneRoom = record => ({
  room_id: record.room_id,
  tenant_id: record.tenant_id,
  name: record.name,
  type: record.type,
  channel: record.channel,
  created_by: record.created_by,
  created_at: record.created_at,
  members: [...record.members],
});

export class MemoryEventStore {
  constructor({ retentionEvents = 1000 } = {}) {
    this.kind = "memory";
    this.durable = false;
    this.retentionEvents = retentionEvents;
    this.channels = new Map();
    this.eventsById = new Map();
    this.eventsByChannel = new Map();
    this.channelSequence = new Map();
    this.apiKeys = new Map();
    this.applications = new Map();
    this.connections = new Map();
    this.rooms = new Map();
  }

  async init() {}

  async health() {
    return { ok: true, kind: this.kind, durable: this.durable };
  }

  async createChannel({ name, tenantId, retention = "memory" }) {
    if (this.channels.has(name)) {
      const error = new Error("channel_exists");
      error.code = "channel_exists";
      throw error;
    }
    const channel = {
      name,
      tenant_id: tenantId,
      retention,
      created_at: new Date().toISOString(),
    };
    this.channels.set(name, channel);
    return channel;
  }

  async listChannels() {
    return [...this.channels.values()];
  }

  async getChannel(name) {
    return this.channels.get(name) || null;
  }

  async deleteChannel(name) {
    const existed = this.channels.delete(name);
    this.eventsByChannel.delete(name);
    this.channelSequence.delete(name);
    return existed;
  }

  async appendEvent({ channel, type, data, principal }) {
    const sequence = (this.channelSequence.get(channel) || 0) + 1;
    this.channelSequence.set(channel, sequence);
    const event = {
      id: crypto.randomUUID(),
      sequence,
      channel,
      type,
      timestamp: new Date().toISOString(),
      source: principal.application_id || principal.sub,
      tenant_id: principal.tenant_id,
      correlation_id: data.correlation_id,
      causation_id: data.causation_id,
      trace_id: data.trace_id,
      data: data.data,
    };
    this.eventsById.set(event.id, event);
    const history = this.eventsByChannel.get(channel) || [];
    history.push(event);
    if (history.length > this.retentionEvents) {
      const removed = history.splice(0, history.length - this.retentionEvents);
      for (const old of removed) this.eventsById.delete(old.id);
    }
    this.eventsByChannel.set(channel, history);
    return event;
  }

  async getEvent(id) {
    return this.eventsById.get(id) || null;
  }

  async listEvents(channel, { after = 0, before = null, limit = 100, type = null } = {}) {
    let items = this.eventsByChannel.get(channel) || [];
    items = items.filter(event => event.sequence > after);
    if (before !== null) items = items.filter(event => event.sequence < before);
    if (type) items = items.filter(event => event.type === type);
    items = items.slice(0, limit);
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
    if (this.apiKeys.has(id)) throw new Error("api_key_exists");
    const record = {
      id,
      key_hash: hash,
      prefix,
      owner,
      tenant_id: tenantId,
      permissions: [...permissions],
      created_at: new Date().toISOString(),
      expires_at: expiresAt,
      last_used_at: null,
      revoked_at: null,
    };
    this.apiKeys.set(id, record);
    return apiKeyMetadata(record);
  }

  async listApiKeys(tenantId) {
    return [...this.apiKeys.values()]
      .filter(record => record.tenant_id === tenantId)
      .map(apiKeyMetadata);
  }

  async getApiKeyMetadata(id) {
    const record = this.apiKeys.get(id);
    return record ? apiKeyMetadata(record) : null;
  }

  async getApiKeyAuthRecord(id) {
    const record = this.apiKeys.get(id);
    return record ? { ...record, permissions: [...record.permissions] } : null;
  }

  async revokeApiKey(id, tenantId) {
    const record = this.apiKeys.get(id);
    if (!record || record.tenant_id !== tenantId) return false;
    if (!record.revoked_at) record.revoked_at = new Date().toISOString();
    return true;
  }

  async touchApiKey(id) {
    const record = this.apiKeys.get(id);
    if (record) record.last_used_at = new Date().toISOString();
  }

  async createApplication({
    applicationId,
    name,
    tenantId,
    permissions = [],
    rateLimits = {},
    allowedOrigins = [],
  }) {
    if (this.applications.has(applicationId)) throw new Error("application_exists");
    const record = {
      application_id: applicationId,
      name,
      tenant_id: tenantId,
      status: "active",
      permissions: [...permissions],
      rate_limits: { ...rateLimits },
      allowed_origins: [...allowedOrigins],
      created_at: new Date().toISOString(),
    };
    this.applications.set(applicationId, record);
    return cloneApplication(record);
  }

  async listApplications(tenantId) {
    return [...this.applications.values()]
      .filter(record => record.tenant_id === tenantId)
      .map(cloneApplication);
  }

  async getApplication(applicationId, tenantId) {
    const record = this.applications.get(applicationId);
    return record && record.tenant_id === tenantId ? cloneApplication(record) : null;
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
    const now = new Date().toISOString();
    const record = {
      connection_id: connectionId,
      principal_id: principalId,
      application_id: applicationId,
      tenant_id: tenantId,
      node_id: nodeId,
      connected_at: now,
      last_seen: now,
      disconnected_at: null,
      status: "active",
      remote_address: remoteAddress,
      user_agent: userAgent,
      subscriptions: [],
      bytes_in: 0,
      bytes_out: 0,
      messages_in: 0,
      messages_out: 0,
    };
    this.connections.set(connectionId, record);
    return cloneConnection(record);
  }

  async updateConnection(connectionId, {
    subscriptions,
    bytesIn = 0,
    bytesOut = 0,
    messagesIn = 0,
    messagesOut = 0,
  } = {}) {
    const record = this.connections.get(connectionId);
    if (!record) return null;
    record.last_seen = new Date().toISOString();
    if (subscriptions) record.subscriptions = [...subscriptions];
    record.bytes_in += bytesIn;
    record.bytes_out += bytesOut;
    record.messages_in += messagesIn;
    record.messages_out += messagesOut;
    return cloneConnection(record);
  }

  async closeConnection(connectionId) {
    const record = this.connections.get(connectionId);
    if (!record) return false;
    if (record.status !== "closed") {
      record.status = "closed";
      record.disconnected_at = new Date().toISOString();
      record.last_seen = record.disconnected_at;
    }
    return true;
  }

  async listConnections(tenantId, { activeOnly = false } = {}) {
    return [...this.connections.values()]
      .filter(record => record.tenant_id === tenantId && (!activeOnly || record.status === "active"))
      .map(cloneConnection);
  }

  async getConnection(connectionId, tenantId) {
    const record = this.connections.get(connectionId);
    return record && record.tenant_id === tenantId ? cloneConnection(record) : null;
  }

  async listPresence(channel, tenantId) {
    return [...this.connections.values()]
      .filter(
        record =>
          record.tenant_id === tenantId &&
          record.status === "active" &&
          record.subscriptions.includes(channel),
      )
      .map(record => ({
        connection_id: record.connection_id,
        principal_id: record.principal_id,
        application_id: record.application_id,
        connected_at: record.connected_at,
        last_seen: record.last_seen,
      }));
  }

  async createRoom({ roomId, tenantId, name, type, createdBy, channel }) {
    if (this.rooms.has(roomId)) throw new Error("room_exists");
    if (this.channels.has(channel)) throw new Error("channel_exists");
    const createdAt = new Date().toISOString();
    const room = {
      room_id: roomId,
      tenant_id: tenantId,
      name,
      type,
      channel,
      created_by: createdBy,
      created_at: createdAt,
      members: [],
    };
    const channelRecord = {
      name: channel,
      tenant_id: tenantId,
      retention: "24h",
      created_at: createdAt,
    };
    this.rooms.set(roomId, room);
    this.channels.set(channel, channelRecord);
    return cloneRoom(room);
  }

  async getRoom(roomId, tenantId) {
    const room = this.rooms.get(roomId);
    return room && room.tenant_id === tenantId ? cloneRoom(room) : null;
  }

  async deleteRoom(roomId, tenantId) {
    const room = this.rooms.get(roomId);
    if (!room || room.tenant_id !== tenantId) return false;
    this.rooms.delete(roomId);
    this.channels.delete(room.channel);
    this.eventsByChannel.delete(room.channel);
    this.channelSequence.delete(room.channel);
    return true;
  }

  async joinRoom(roomId, tenantId, principalId) {
    const room = this.rooms.get(roomId);
    if (!room || room.tenant_id !== tenantId) return null;
    if (!room.members.includes(principalId)) room.members.push(principalId);
    return cloneRoom(room);
  }

  async leaveRoom(roomId, tenantId, principalId) {
    const room = this.rooms.get(roomId);
    if (!room || room.tenant_id !== tenantId) return null;
    room.members = room.members.filter(member => member !== principalId);
    return cloneRoom(room);
  }

  async close() {}
}
