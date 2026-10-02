import { MemoryBroker } from "./broker/memory.js";
import { NatsJetStreamBroker } from "./broker/nats.js";
import { MemoryEventStore } from "./persistence/memory.js";
import { PostgresEventStore } from "./persistence/postgres.js";

const mode = (value, fallback) => String(value || fallback).trim().toLowerCase();

export async function createRuntime(env = process.env) {
  const persistenceMode = mode(env.REALTIME_PERSISTENCE_MODE, "memory");
  const brokerMode = mode(env.REALTIME_BROKER_MODE, "memory");

  let eventStore;
  if (persistenceMode === "memory") {
    eventStore = new MemoryEventStore({
      retentionEvents: Number(env.REALTIME_MEMORY_RETENTION_EVENTS || 1000),
    });
  } else if (persistenceMode === "postgres") {
    eventStore = new PostgresEventStore({
      connectionString: env.REALTIME_DATABASE_URL,
      max: Number(env.REALTIME_DATABASE_POOL_MAX || 10),
      ssl: String(env.REALTIME_DATABASE_SSL || "false").toLowerCase() === "true"
        ? { rejectUnauthorized: true }
        : false,
    });
  } else {
    throw new Error(`unsupported REALTIME_PERSISTENCE_MODE: ${persistenceMode}`);
  }

  let broker;
  if (brokerMode === "memory") {
    broker = new MemoryBroker();
  } else if (brokerMode === "nats" || brokerMode === "nats-jetstream") {
    broker = await NatsJetStreamBroker.connect({
      servers: env.REALTIME_NATS_URL || "nats://127.0.0.1:4222",
      name: env.REALTIME_NODE_ID || "codestra-realtime",
      streamName: env.REALTIME_NATS_STREAM || "REALTIME_EVENTS",
      prefix: env.REALTIME_NATS_SUBJECT_PREFIX || "realtime.events",
      maxAgeNanos: Number(env.REALTIME_NATS_MAX_AGE_NANOS || 604800000000000),
    });
  } else {
    throw new Error(`unsupported REALTIME_BROKER_MODE: ${brokerMode}`);
  }

  await eventStore.init();

  const requireDurable = String(env.REALTIME_REQUIRE_DURABLE || "false").toLowerCase() === "true";
  if (requireDurable && (!eventStore.durable || !broker.durable)) {
    await Promise.allSettled([broker.close(), eventStore.close()]);
    throw new Error("REALTIME_REQUIRE_DURABLE requires postgres persistence and NATS JetStream");
  }

  return {
    eventStore,
    broker,
    async close() {
      await Promise.allSettled([broker.close(), eventStore.close()]);
    },
  };
}
