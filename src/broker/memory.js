export class MemoryBroker {
  constructor() {
    this.kind = "memory";
    this.durable = false;
    this.closed = false;
    this.subscribers = new Map();
  }

  async publish(channel, event) {
    if (this.closed) throw new Error("broker_closed");
    const handlers = [...(this.subscribers.get(channel) || [])];
    await Promise.all(handlers.map(handler => handler(event)));
  }

  async subscribe(channel, handler) {
    if (this.closed) throw new Error("broker_closed");
    const handlers = this.subscribers.get(channel) || new Set();
    handlers.add(handler);
    this.subscribers.set(channel, handlers);
    let active = true;
    return async () => {
      if (!active) return;
      active = false;
      handlers.delete(handler);
      if (!handlers.size) this.subscribers.delete(channel);
    };
  }

  async replay() {
    return [];
  }

  async ack() {
    return true;
  }

  async health() {
    return { ok: !this.closed, kind: this.kind, durable: this.durable };
  }

  async close() {
    this.closed = true;
    this.subscribers.clear();
  }
}
