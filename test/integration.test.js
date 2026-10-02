import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { WebSocket } from "ws";
import { createRuntime } from "../src/runtime.js";
import { createGateway, REALTIME_PROTOCOL } from "../src/server.js";

const enabled = process.env.REALTIME_INTEGRATION === "1";
const bootstrap = process.env.REALTIME_BOOTSTRAP_API_KEY || "integration-bootstrap-secret";
const tenant = process.env.REALTIME_BOOTSTRAP_TENANT || "integration";

async function startNode(nodeId) {
  const env = {
    ...process.env,
    REALTIME_AUTH_MODE: "api_key",
    REALTIME_BOOTSTRAP_API_KEY: bootstrap,
    REALTIME_BOOTSTRAP_TENANT: tenant,
    REALTIME_PERSISTENCE_MODE: "postgres",
    REALTIME_BROKER_MODE: "nats",
    REALTIME_REQUIRE_DURABLE: "true",
    REALTIME_NODE_ID: nodeId,
  };
  const runtime = await createRuntime(env);
  const gateway = createGateway({ env, ...runtime });
  await new Promise(resolve => gateway.server.listen(0, "127.0.0.1", resolve));
  return {
    env,
    runtime,
    gateway,
    port: gateway.server.address().port,
    async close() {
      await gateway.shutdown();
      await runtime.close();
    },
  };
}

async function waitUntil(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error("condition timeout");
}

function authHeaders(extra = {}) {
  return {
    authorization: `Bearer ${bootstrap}`,
    ...extra,
  };
}

async function openSocket(port) {
  const ws = new WebSocket(
    `ws://127.0.0.1:${port}/ws`,
    [REALTIME_PROTOCOL, `bearer.${bootstrap}`],
  );
  const received = [];
  ws.on("message", data => received.push(JSON.parse(data.toString())));
  await new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
  return { ws, received };
}

test(
  "PostgreSQL + NATS provide durable platform state, restart replay, presence, and cross-node fanout",
  { skip: !enabled, timeout: 30000 },
  async () => {
    const suffix = crypto.randomBytes(6).toString("hex");
    const node1 = await startNode("integration-node-1");
    const node2 = await startNode("integration-node-2");

    let room;
    let published;
    let connectionId;
    try {
      let response = await fetch(`http://127.0.0.1:${node1.port}/v1/applications`, {
        method: "POST",
        headers: authHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({
          name: `Integration App ${suffix}`,
          permissions: ["channel:read", "channel:subscribe"],
          allowed_origins: ["https://integration.example.test"],
        }),
      });
      assert.equal(response.status, 201);
      const application = await response.json();
      assert.match(application.application_id, /^app_[a-f0-9]{24}$/);

      response = await fetch(`http://127.0.0.1:${node1.port}/v1/rooms`, {
        method: "POST",
        headers: authHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ name: `Integration Room ${suffix}`, type: "video" }),
      });
      assert.equal(response.status, 201);
      room = await response.json();
      assert.equal(room.tenant_id, tenant);

      const { ws, received } = await openSocket(node2.port);
      await waitUntil(() => received.some(message => message.op === "connected"));
      connectionId = received.find(message => message.op === "connected").connection_id;
      ws.send(JSON.stringify({ op: "subscribe", channel: room.channel }));
      await waitUntil(() => received.some(message => message.op === "subscribed"));

      response = await fetch(
        `http://127.0.0.1:${node1.port}/v1/presence/${encodeURIComponent(room.channel)}`,
        { headers: authHeaders() },
      );
      assert.equal(response.status, 200);
      const presence = await response.json();
      assert.equal(presence.count, 1);
      assert.equal(presence.items[0].connection_id, connectionId);

      const eventRequest = {
        channel: room.channel,
        type: "integration.cross-node",
        data: { source: "node-1" },
      };
      response = await fetch(`http://127.0.0.1:${node1.port}/v1/events`, {
        method: "POST",
        headers: authHeaders({
          "content-type": "application/json",
          "idempotency-key": `integration-event-${suffix}`,
        }),
        body: JSON.stringify(eventRequest),
      });
      assert.equal(response.status, 202);
      published = await response.json();

      await waitUntil(() =>
        received.some(
          message =>
            message.op === "event" &&
            message.event.id === published.id &&
            message.event.data.source === "node-1",
        ),
      );
      const firstDeliveryCount = received.filter(
        message => message.op === "event" && message.event.id === published.id,
      ).length;

      response = await fetch(`http://127.0.0.1:${node1.port}/v1/events`, {
        method: "POST",
        headers: authHeaders({
          "content-type": "application/json",
          "idempotency-key": `integration-event-${suffix}`,
        }),
        body: JSON.stringify(eventRequest),
      });
      assert.equal(response.status, 202);
      assert.equal(response.headers.get("idempotency-replayed"), "true");
      assert.equal((await response.json()).id, published.id);
      await new Promise(resolve => setTimeout(resolve, 100));
      assert.equal(
        received.filter(
          message => message.op === "event" && message.event.id === published.id,
        ).length,
        firstDeliveryCount,
      );

      response = await fetch(
        `http://127.0.0.1:${node1.port}/v1/connections/${connectionId}`,
        { headers: authHeaders() },
      );
      assert.equal(response.status, 200);
      const connection = await response.json();
      assert.equal(connection.node_id, "integration-node-2");
      assert.deepEqual(connection.subscriptions, [room.channel]);
      ws.close();
    } finally {
      await node1.close();
      await node2.close();
    }

    const restarted = await startNode("integration-node-restarted");
    try {
      let response = await fetch(
        `http://127.0.0.1:${restarted.port}/v1/rooms/${room.room_id}`,
        { headers: authHeaders() },
      );
      assert.equal(response.status, 200);
      assert.equal((await response.json()).channel, room.channel);

      const { ws, received } = await openSocket(restarted.port);
      await waitUntil(() => received.some(message => message.op === "connected"));
      ws.send(JSON.stringify({ op: "resume", channel: room.channel, after: 0 }));
      await waitUntil(() => received.some(message => message.op === "resumed"));
      const replay = received.find(
        message =>
          message.op === "event" &&
          message.replay === true &&
          message.event.id === published.id,
      );
      assert.ok(replay, "persisted event must replay after node restart");
      assert.equal(replay.event.sequence, published.sequence);
      ws.close();

      response = await fetch(
        `http://127.0.0.1:${restarted.port}/v1/rooms/${room.room_id}`,
        {
          method: "DELETE",
          headers: authHeaders(),
        },
      );
      assert.equal(response.status, 204);
    } finally {
      await restarted.close();
    }
  },
);
