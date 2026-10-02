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

  async close() {}
}
