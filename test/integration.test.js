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
  "PostgreSQL + NATS provide durable restart replay and cross-node fanout",
  { skip: !enabled, timeout: 30000 },
  async () => {
    const suffix = crypto.randomBytes(6).toString("hex");
    const channel = `tenant/${tenant}/integration-${suffix}`;
    const node1 = await startNode("integration-node-1");
    const node2 = await startNode("integration-node-2");

    let published;
    try {
      let response = await fetch(`http://127.0.0.1:${node1.port}/v1/channels`, {
        method: "POST",
        headers: authHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({ name: channel }),
      });
      assert.equal(response.status, 201);

      const { ws, received } = await openSocket(node2.port);
      ws.send(JSON.stringify({ op: "subscribe", channel }));
      await waitUntil(() => received.some(message => message.op === "subscribed"));

      response = await fetch(`http://127.0.0.1:${node1.port}/v1/events`, {
        method: "POST",
        headers: authHeaders({ "content-type": "application/json" }),
        body: JSON.stringify({
          channel,
          type: "integration.cross-node",
          data: { source: "node-1" },
        }),
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
      ws.close();
    } finally {
      await node1.close();
      await node2.close();
    }

    const restarted = await startNode("integration-node-restarted");
    try {
      const { ws, received } = await openSocket(restarted.port);
      ws.send(JSON.stringify({ op: "resume", channel, after: 0 }));
      await waitUntil(() => received.some(message => message.op === "resumed"));
      const replay = received.find(
        message => message.op === "event" && message.replay === true && message.event.id === published.id,
      );
      assert.ok(replay, "persisted event must replay after node restart");
      assert.equal(replay.event.sequence, published.sequence);
      ws.close();

      const response = await fetch(
        `http://127.0.0.1:${restarted.port}/v1/channels/${encodeURIComponent(channel)}`,
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
