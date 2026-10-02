import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { WebSocket } from "ws";
import {
  createGateway,
  validEvent,
  REALTIME_PROTOCOL,
  assertSafeBind,
} from "../src/server.js";
import { MemoryBroker } from "../src/broker/memory.js";
import { MemoryEventStore } from "../src/persistence/memory.js";

const env = { REALTIME_AUTH_MODE: "disabled" };

const base = (over = {}) => ({
  event_id: crypto.randomUUID(),
  sequence_no: 1,
  namespace: "mission",
  event_type: "state_transition",
  timestamp: new Date().toISOString(),
  source_service: "test",
  payload: {
    task_id: "T1",
    previous_state: "ACTIVE",
    new_state: "TESTING",
    target_sha: "a".repeat(40),
    triggered_by: "tester",
  },
  ...over,
});

async function startGateway(options = {}) {
  const gateway = createGateway({ env, ...options });
  await new Promise(resolve => gateway.server.listen(0, "127.0.0.1", resolve));
  return {
    gateway,
    port: gateway.server.address().port,
    async close() {
      await gateway.shutdown();
    },
  };
}

async function withServer(fn) {
  const running = await startGateway();
  try {
    return await fn(running.port);
  } finally {
    await running.close();
  }
}

async function openSocket(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, REALTIME_PROTOCOL);
  const received = [];
  ws.on("message", data => received.push(JSON.parse(data.toString())));
  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  return { ws, received };
}

async function waitUntil(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error("condition timeout");
}

test("accepts strict governed envelope", () => assert.equal(validEvent(base()), true));

test("rejects legacy and unknown namespace", () => {
  assert.equal(validEvent({ type: "mission.x", ts: new Date().toISOString(), payload: {} }), false);
  assert.equal(validEvent(base({ namespace: "evil" })), false);
});

test("validates heartbeat payload", () =>
  assert.equal(
    validEvent(
      base({
        namespace: "agent",
        event_type: "heartbeat",
        payload: {
          agent_id: "A",
          task_id: "T",
          current_sha: "b".repeat(40),
          status: "ACTIVE",
          changed_files_count: 0,
        },
      }),
    ),
    true,
  ));

test("canonical health and system endpoints expose standalone contract", () =>
  withServer(async port => {
    const live = await fetch(`http://127.0.0.1:${port}/health/live`);
    assert.equal(live.status, 200);
    assert.equal(live.headers.has("x-request-id"), true);

    const readyResponse = await fetch(`http://127.0.0.1:${port}/health/ready`);
    assert.equal(readyResponse.status, 200);
    const ready = await readyResponse.json();
    assert.equal(ready.ready, true);
    assert.equal(ready.dependencies.broker.kind, "memory");
    assert.equal(ready.dependencies.persistence.kind, "memory");

    const caps = await (
      await fetch(`http://127.0.0.1:${port}/v1/system/capabilities`)
    ).json();
    assert.equal(caps.service, "codestra-realtime");
    assert.equal(caps.capabilities.websocket, true);
    assert.equal(caps.capabilities.replay, true);
    assert.equal(caps.capabilities.durable_replay, false);
  }));

test("channel CRUD and HTTP event delivery/history work through v1", () =>
  withServer(async port => {
    const channel = "tenant/local/orders";
    let response = await fetch(`http://127.0.0.1:${port}/v1/channels`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: channel }),
    });
    assert.equal(response.status, 201);

    response = await fetch(`http://127.0.0.1:${port}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        channel,
        type: "order.updated",
        data: { order_id: "ORD-500" },
      }),
    });
    assert.equal(response.status, 202);
    const event = await response.json();
    assert.equal(event.sequence, 1);
    assert.equal(event.channel, channel);
    assert.equal(event.tenant_id, "local");
    assert.match(event.id, /^[0-9a-f-]{36}$/);

    const fetched = await (
      await fetch(`http://127.0.0.1:${port}/v1/events/${event.id}`)
    ).json();
    assert.equal(fetched.type, "order.updated");

    const history = await (
      await fetch(
        `http://127.0.0.1:${port}/v1/channels/${encodeURIComponent(channel)}/events?after=0&limit=10`,
      )
    ).json();
    assert.equal(history.items.length, 1);
    assert.equal(history.items[0].id, event.id);
  }));

test("publishing to an unknown channel fails closed", () =>
  withServer(async port => {
    const response = await fetch(`http://127.0.0.1:${port}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        channel: "tenant/local/missing",
        type: "test",
        data: {},
      }),
    });
    assert.equal(response.status, 404);
    const body = await response.json();
    assert.equal(body.error.code, "channel_not_found");
  }));

test("websocket canonical protocol subscribes and receives published event", () =>
  withServer(async port => {
    const channel = "tenant/local/chat/support";
    await fetch(`http://127.0.0.1:${port}/v1/channels`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: channel }),
    });

    const { ws, received } = await openSocket(port);
    ws.send(JSON.stringify({ op: "subscribe", channel }));
    await waitUntil(() => received.some(message => message.op === "subscribed"));

    ws.send(
      JSON.stringify({
        op: "publish",
        channel,
        type: "chat.message",
        data: { text: "hello" },
      }),
    );
    await waitUntil(() => received.some(message => message.op === "event"));

    const event = received.find(message => message.op === "event").event;
    assert.equal(event.data.text, "hello");
    assert.equal(event.sequence, 1);
    assert.equal(received.some(message => message.op === "published"), true);
    ws.close();
  }));

test("resume replays missed events after gateway process state is recreated", async () => {
  const eventStore = new MemoryEventStore({ retentionEvents: 100 });
  const first = await startGateway({
    eventStore,
    broker: new MemoryBroker(),
  });
  const channel = "tenant/local/restart";

  try {
    await fetch(`http://127.0.0.1:${first.port}/v1/channels`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: channel }),
    });
    for (const value of [1, 2, 3]) {
      const response = await fetch(`http://127.0.0.1:${first.port}/v1/events`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ channel, type: "counter", data: { value } }),
      });
      assert.equal(response.status, 202);
    }
  } finally {
    await first.close();
  }

  const second = await startGateway({
    eventStore,
    broker: new MemoryBroker(),
  });
  try {
    const { ws, received } = await openSocket(second.port);
    ws.send(JSON.stringify({ op: "resume", channel, after: 1 }));
    await waitUntil(() => received.some(message => message.op === "resumed"));

    const replayed = received
      .filter(message => message.op === "event" && message.replay === true)
      .map(message => message.event.sequence);
    assert.deepEqual(replayed, [2, 3]);
    assert.equal(received.find(message => message.op === "resumed").replayed, 2);
    ws.close();
  } finally {
    await second.close();
  }
});

test("shared broker fans out publish from node 1 to subscriber on node 2", async () => {
  const eventStore = new MemoryEventStore({ retentionEvents: 100 });
  const broker = new MemoryBroker();
  const node1 = await startGateway({ eventStore, broker });
  const node2 = await startGateway({ eventStore, broker });
  const channel = "tenant/local/multi-node";

  try {
    await fetch(`http://127.0.0.1:${node1.port}/v1/channels`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: channel }),
    });

    const { ws, received } = await openSocket(node2.port);
    ws.send(JSON.stringify({ op: "subscribe", channel }));
    await waitUntil(() => received.some(message => message.op === "subscribed"));

    const response = await fetch(`http://127.0.0.1:${node1.port}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        channel,
        type: "cross.node",
        data: { node: 1 },
      }),
    });
    assert.equal(response.status, 202);

    await waitUntil(() =>
      received.some(
        message =>
          message.op === "event" &&
          message.event.type === "cross.node" &&
          message.event.data.node === 1,
      ),
    );
    ws.close();
  } finally {
    await node1.close();
    await node2.close();
    await broker.close();
  }
});

test("standalone API-key mode issues, authenticates, rotates, and revokes keys", async () => {
  const apiEnv = {
    REALTIME_AUTH_MODE: "api_key",
    REALTIME_BOOTSTRAP_API_KEY: "bootstrap-local-secret-please-change",
    REALTIME_BOOTSTRAP_TENANT: "tenant-a",
  };
  const running = await startGateway({ env: apiEnv });
  try {
    const bootstrapHeaders = {
      authorization: "Bearer bootstrap-local-secret-please-change",
      "content-type": "application/json",
    };
    let response = await fetch(`http://127.0.0.1:${running.port}/v1/api-keys`, {
      method: "POST",
      headers: bootstrapHeaders,
      body: JSON.stringify({
        owner: "test-app",
        permissions: [
          "channel:create",
          "channel:read",
          "channel:publish",
          "channel:subscribe",
          "event:publish",
          "event:read",
        ],
      }),
    });
    assert.equal(response.status, 201);
    const issued = await response.json();
    assert.match(issued.api_key, /^rt_live_[a-f0-9]{16}_/);
    assert.equal("key_hash" in issued, false);

    response = await fetch(`http://127.0.0.1:${running.port}/v1/api-keys`, {
      headers: { authorization: "Bearer bootstrap-local-secret-please-change" },
    });
    assert.equal(response.status, 200);
    const list = await response.json();
    assert.equal(list.items.length, 1);
    assert.equal("api_key" in list.items[0], false);
    assert.equal("key_hash" in list.items[0], false);

    response = await fetch(`http://127.0.0.1:${running.port}/v1/channels`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${issued.api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ name: "tenant/tenant-a/api-key-test" }),
    });
    assert.equal(response.status, 201);

    response = await fetch(
      `http://127.0.0.1:${running.port}/v1/api-keys/${issued.id}/rotate`,
      {
        method: "POST",
        headers: { authorization: "Bearer bootstrap-local-secret-please-change" },
      },
    );
    assert.equal(response.status, 201);
    const rotated = await response.json();
    assert.notEqual(rotated.api_key, issued.api_key);
    assert.equal(rotated.rotated_from, issued.id);

    response = await fetch(`http://127.0.0.1:${running.port}/v1/channels`, {
      headers: { authorization: `Bearer ${issued.api_key}` },
    });
    assert.equal(response.status, 401);

    response = await fetch(`http://127.0.0.1:${running.port}/v1/channels`, {
      headers: { authorization: `Bearer ${rotated.api_key}` },
    });
    assert.equal(response.status, 200);
  } finally {
    await running.close();
  }
});

test("legacy http ingest remains compatible and rejects replay", () =>
  withServer(async port => {
    const event = base();
    let response = await fetch(`http://127.0.0.1:${port}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
    });
    assert.equal(response.status, 202);

    response = await fetch(`http://127.0.0.1:${port}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
    });
    assert.equal(response.status, 409);
  }));

test("legacy health remains compatible", () =>
  withServer(async port => {
    const body = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json();
    assert.equal(body.ok, true);
    assert.equal(body.auth_mode, "disabled");
  }));

test("rejects unknown governed event type and invalid previous state", () => {
  assert.equal(validEvent(base({ event_type: "typo", payload: { x: 1 } })), false);
  assert.equal(
    validEvent(
      base({
        payload: {
          task_id: "T1",
          previous_state: "garbage",
          new_state: "TESTING",
          target_sha: "a".repeat(40),
          triggered_by: "tester",
        },
      }),
    ),
    false,
  );
});

test("maps event permissions by type", async () => {
  const { writePermission, readPermission } = await import("../src/server.js");
  assert.equal(writePermission(base()), "mission:write");
  assert.equal(
    writePermission(
      base({
        namespace: "certification",
        event_type: "evidence_submitted",
        payload: {
          certification_id: crypto.randomUUID(),
          task_id: "T",
          exact_sha: "a".repeat(40),
          test_pass_rate: 100,
          artifact_url: "https://example.test/a",
        },
      }),
    ),
    "evidence:submit",
  );
  assert.equal(
    readPermission(
      base({
        namespace: "agent",
        event_type: "heartbeat",
        payload: {
          agent_id: "A",
          task_id: "T",
          current_sha: "a".repeat(40),
          status: "ACTIVE",
          changed_files_count: 0,
        },
      }),
    ),
    "agent:read",
  );
});

test("auth disabled refuses non-loopback public bind", () => {
  assert.throws(
    () => assertSafeBind({ REALTIME_AUTH_MODE: "disabled" }, "0.0.0.0"),
    /loopback/,
  );
  assert.equal(
    assertSafeBind({ REALTIME_AUTH_MODE: "disabled" }, "127.0.0.1"),
    "127.0.0.1",
  );
});
