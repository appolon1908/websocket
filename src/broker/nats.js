import { connect } from "@nats-io/transport-node";
import {
  jetstream,
  jetstreamManager,
  RetentionPolicy,
  StorageType,
} from "@nats-io/jetstream";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const subjectToken = channel => Buffer.from(channel, "utf8").toString("base64url");

export class NatsJetStreamBroker {
  constructor({ connection, stream, prefix = "realtime.events" }) {
    this.kind = "nats-jetstream";
    this.durable = true;
    this.connection = connection;
    this.stream = stream;
    this.prefix = prefix;
  }

  static async connect({
    servers = "nats://127.0.0.1:4222",
    name = "codestra-realtime",
    streamName = "REALTIME_EVENTS",
    prefix = "realtime.events",
    maxAgeNanos = 7 * 24 * 60 * 60 * 1_000_000_000,
  } = {}) {
    const connection = await connect({
      servers: String(servers).split(",").map(value => value.trim()).filter(Boolean),
      name,
    });
    const manager = await jetstreamManager(connection);
    try {
      await manager.streams.info(streamName);
    } catch (error) {
      if (error?.code !== "404" && error?.api_error?.code !== 404) {
        await connection.close();
        throw error;
      }
      await manager.streams.add({
        name: streamName,
        subjects: [`${prefix}.>`],
        retention: RetentionPolicy.Limits,
        storage: StorageType.File,
        max_age: maxAgeNanos,
      });
    }
    return new NatsJetStreamBroker({
      connection,
      stream: jetstream(connection),
      prefix,
    });
  }

  subject(channel) {
    return `${this.prefix}.${subjectToken(channel)}`;
  }

  async publish(channel, event) {
    await this.stream.publish(this.subject(channel), encoder.encode(JSON.stringify(event)));
  }

  async subscribe(channel, handler) {
    const subscription = this.connection.subscribe(this.subject(channel));
    await this.connection.flush();
    let active = true;
    const task = (async () => {
      try {
        for await (const message of subscription) {
          if (!active) break;
          const event = JSON.parse(decoder.decode(message.data));
          await handler(event);
        }
      } catch {
        if (active && !this.connection.isClosed()) throw new Error("nats_subscription_failed");
      }
    })();
    task.catch(() => {});
    return async () => {
      active = false;
      subscription.unsubscribe();
    };
  }

  async replay() {
    return [];
  }

  async ack() {
    return true;
  }

  async health() {
    return {
      ok: !this.connection.isClosed(),
      kind: this.kind,
      durable: this.durable,
    };
  }

  async close() {
    if (!this.connection.isClosed()) {
      await this.connection.drain();
    }
  }
}
