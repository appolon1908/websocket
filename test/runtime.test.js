import test from "node:test";
import assert from "node:assert/strict";
import { createRuntime } from "../src/runtime.js";

test("standalone runtime defaults to memory adapters for development", async () => {
  const runtime = await createRuntime({});
  try {
    assert.equal(runtime.eventStore.kind, "memory");
    assert.equal(runtime.broker.kind, "memory");
    assert.equal(runtime.eventStore.durable, false);
    assert.equal(runtime.broker.durable, false);
  } finally {
    await runtime.close();
  }
});

test("durable-required mode refuses memory-only runtime", async () => {
  await assert.rejects(
    createRuntime({ REALTIME_REQUIRE_DURABLE: "true" }),
    /requires postgres persistence and NATS JetStream/,
  );
});
