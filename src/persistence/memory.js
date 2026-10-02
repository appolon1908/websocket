import crypto from "node:crypto";

export class MemoryEventStore {
  constructor({ retentionEvents = 1000 } = {}) {
    this.kind = "memory";
    this.durable = false;
    this.retentionEvents = retentionEvents;
    this.channels = new Map();
    this.eventsById = new Map();
    this.eventsByChannel = new Map();
    this.channelSequence = new Map();
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

  async close() {}
}
