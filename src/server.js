import http from "node:http";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { WebSocketServer } from "ws";
import { MemoryBroker } from "./broker/memory.js";
import { MemoryEventStore } from "./persistence/memory.js";
import { createRuntime } from "./runtime.js";
import { authenticateApiKey, generateApiKey } from "./auth/api-key.js";

export const REALTIME_PROTOCOL = "codestra.realtime.v1";
export const allowedNamespaces = new Set([
  "agent",
  "mission",
  "ci",
  "repo",
  "notification",
  "pr",
  "review",
  "testing",
  "certification",
]);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[0-9a-f]{40}$/;
const states = new Set([
  "QUEUED",
  "ASSIGNED",
  "LEASED",
  "STARTING",
  "ACTIVE",
  "TESTING",
  "CHECKPOINTED",
  "IN_REVIEW",
  "CERTIFICATION",
  "COMPLETED",
  "BLOCKED",
  "STALLED",
  "STOPPED",
  "FAILED",
]);
const roles = {
  Administrator: new Set(["*"]),
  Operator: new Set([
    "mission:read",
    "mission:write",
    "agent:assign",
    "agent:stop",
    "router:lease",
    "channel:create",
    "channel:read",
    "channel:publish",
    "channel:subscribe",
    "event:publish",
    "event:read",
  ]),
  Reviewer: new Set([
    "mission:read",
    "evidence:read",
    "evidence:certify",
    "review:approve",
    "pr:link",
    "agent:read",
    "channel:read",
    "channel:subscribe",
    "event:read",
  ]),
  Viewer: new Set([
    "mission:read",
    "evidence:read",
    "agent:read",
    "channel:read",
    "channel:subscribe",
    "event:read",
  ]),
  Agent: new Set([
    "agent:heartbeat",
    "agent:checkpoint",
    "evidence:submit",
    "task:claim",
    "channel:publish",
    "channel:subscribe",
    "event:publish",
  ]),
};

const b64 = value => Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const jsonPart = value => JSON.parse(b64(value).toString("utf8"));
const allows = (user, permission) => {
  const direct = new Set(user.permissions || []);
  if (direct.has("*") || direct.has(permission)) return true;
  return (user.roles || []).some(
    role => roles[role]?.has("*") || roles[role]?.has(permission),
  );
};
const authMode = env =>
  (env.REALTIME_AUTH_MODE || env.MISSION_CONTROL_AUTH_MODE || "disabled").toLowerCase();

const extractToken = req => {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const protocols = String(req.headers["sec-websocket-protocol"] || "")
    .split(",")
    .map(value => value.trim());
  const bearer = protocols.find(value => value.startsWith("bearer."));
  return bearer ? bearer.slice(7) : null;
};

const sendJson = (res, status, body, requestId) => {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-request-id": requestId,
  });
  res.end(JSON.stringify(body));
};

const sendError = (res, status, code, message, requestId) =>
  sendJson(res, status, { error: { code, message, request_id: requestId } }, requestId);

export function createJwtVerifier(env = process.env) {
  const mode = authMode(env);
  const issuer = (env.REALTIME_JWT_ISSUER || env.MISSION_CONTROL_JWT_ISSUER || "").replace(/\/$/, "");
  const audience =
    env.REALTIME_JWT_AUDIENCE || env.MISSION_CONTROL_JWT_AUDIENCE || "websocket-gateway";
  const allowedAzp = new Set(
    (env.REALTIME_ALLOWED_AZP ||
      env.MISSION_CONTROL_ALLOWED_AZP ||
      "mission-control-ui,mission-control-backend")
      .split(",")
      .filter(Boolean),
  );
  const tenantClaim =
    env.REALTIME_TENANT_CLAIM || env.MISSION_CONTROL_TENANT_CLAIM || "tenant_id";
  let jwks = { expires: 0, keys: new Map() };

  if (["required", "oidc", "jwt"].includes(mode) && !issuer) {
    throw new Error("REALTIME_JWT_ISSUER required");
  }

  async function keyFor(kid) {
    if (Date.now() > jwks.expires || !jwks.keys.has(kid)) {
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        Number(env.REALTIME_JWKS_TIMEOUT_MS || 3000),
      );
      try {
        const res = await fetch(issuer + "/protocol/openid-connect/certs", {
          signal: controller.signal,
        });
        if (!res.ok) throw new Error("jwks_unavailable");
        const raw = Buffer.from(await res.arrayBuffer());
        if (raw.length > Number(env.REALTIME_JWKS_MAX_BYTES || 262144)) {
          throw new Error("jwks_too_large");
        }
        const body = JSON.parse(raw.toString("utf8"));
        jwks = {
          expires: Date.now() + 300000,
          keys: new Map((body.keys || []).map(key => [key.kid, key])),
        };
      } finally {
        clearTimeout(timeout);
      }
    }
    const jwk = jwks.keys.get(kid);
    if (!jwk) throw new Error("unknown_kid");
    return crypto.createPublicKey({ key: jwk, format: "jwk" });
  }

  return async token => {
    if (mode === "disabled") {
      return {
        sub: "local-development",
        roles: ["Administrator"],
        tenant_id: "local",
        application_id: "local-development",
      };
    }
    if (!token) throw new Error("missing_bearer_token");
    if (token.length > Number(env.REALTIME_MAX_TOKEN_BYTES || 16384)) {
      throw new Error("token_too_large");
    }
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("invalid_token");
    const header = jsonPart(parts[0]);
    const claims = jsonPart(parts[1]);
    if (header.alg !== "RS256") throw new Error("invalid_alg");
    const key = await keyFor(header.kid);
    const ok = crypto.verify(
      "RSA-SHA256",
      Buffer.from(parts[0] + "." + parts[1]),
      key,
      b64(parts[2]),
    );
    if (!ok) throw new Error("invalid_signature");

    const now = Math.floor(Date.now() / 1000);
    const skew = Number(env.REALTIME_CLOCK_SKEW_SECONDS || 30);
    if (
      claims.iss !== issuer ||
      !claims.exp ||
      claims.exp <= now - skew ||
      !claims.iat ||
      claims.iat > now + skew ||
      claims.nbf > now + skew
    ) {
      throw new Error("invalid_claims");
    }
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(audience)) throw new Error("invalid_audience");
    if (allowedAzp.size && !allowedAzp.has(claims.azp)) throw new Error("invalid_azp");

    const tenant = claims[tenantClaim];
    if (typeof tenant !== "string" || !tenant) throw new Error("tenant_claim_required");
    const realmRoles = claims.realm_access?.roles || [];
    const clientRoles = claims.resource_access?.["mission-control"]?.roles || [];
    return {
      sub: claims.sub,
      roles: [...new Set([...realmRoles, ...clientRoles])],
      tenant_id: tenant,
      application_id: claims.azp || null,
      claims,
    };
  };
}

export function createAuthenticator({ env = process.env, eventStore }) {
  const mode = authMode(env);
  if (mode === "api_key" || mode === "apikey") {
    return async token => {
      if (!token) throw new Error("missing_bearer_token");
      return authenticateApiKey({ token, eventStore, env });
    };
  }
  if (mode === "disabled") {
    return async () => ({
      sub: "local-development",
      roles: ["Administrator"],
      permissions: ["*"],
      tenant_id: "local",
      application_id: "local-development",
    });
  }
  if (["required", "oidc", "jwt"].includes(mode)) {
    return createJwtVerifier(env);
  }
  throw new Error(`unsupported REALTIME_AUTH_MODE: ${mode}`);
}

function validPayload(event) {
  if (event.namespace === "agent" && event.event_type === "heartbeat") {
    const payload = event.payload;
    return (
      !!payload &&
      typeof payload.agent_id === "string" &&
      typeof payload.task_id === "string" &&
      SHA.test(payload.current_sha || "") &&
      states.has(payload.status) &&
      Number.isInteger(payload.changed_files_count) &&
      payload.changed_files_count >= 0
    );
  }
  if (event.namespace === "mission" && event.event_type === "state_transition") {
    const payload = event.payload;
    return (
      !!payload &&
      typeof payload.task_id === "string" &&
      states.has(payload.previous_state) &&
      states.has(payload.new_state) &&
      SHA.test(payload.target_sha || "") &&
      typeof payload.triggered_by === "string"
    );
  }
  if (event.namespace === "mission" && event.event_type === "task.claimed") {
    const payload = event.payload;
    return (
      !!payload &&
      typeof payload.task_id === "string" &&
      typeof payload.agent_id === "string" &&
      typeof payload.repository === "string"
    );
  }
  if (event.namespace === "certification" && event.event_type === "evidence_submitted") {
    const payload = event.payload;
    return (
      !!payload &&
      UUID.test(payload.certification_id || "") &&
      typeof payload.task_id === "string" &&
      SHA.test(payload.exact_sha || "") &&
      typeof payload.test_pass_rate === "number" &&
      payload.test_pass_rate >= 0 &&
      payload.test_pass_rate <= 100 &&
      typeof payload.artifact_url === "string"
    );
  }
  return (
    [
      "ci.status",
      "repo.state_changed",
      "notification.created",
      "pr.updated",
      "review.updated",
      "testing.result",
    ].includes(event.namespace + "." + event.event_type) &&
    Object.keys(event.payload || {}).length > 0
  );
}

export function validEvent(event) {
  return (
    !!event &&
    typeof event === "object" &&
    UUID.test(event.event_id || "") &&
    Number.isInteger(event.sequence_no) &&
    event.sequence_no >= 1 &&
    allowedNamespaces.has(event.namespace) &&
    typeof event.event_type === "string" &&
    event.event_type.length > 0 &&
    typeof event.timestamp === "string" &&
    !Number.isNaN(Date.parse(event.timestamp)) &&
    typeof event.source_service === "string" &&
    event.source_service.length > 0 &&
    event.payload &&
    typeof event.payload === "object" &&
    !Array.isArray(event.payload) &&
    (!event.correlation_id || UUID.test(event.correlation_id)) &&
    (!event.causation_id || UUID.test(event.causation_id)) &&
    validPayload(event)
  );
}

export function writePermission(event) {
  const key = event.namespace + "." + event.event_type;
  if (key === "agent.heartbeat") return "agent:heartbeat";
  if (key.startsWith("mission.")) return "mission:write";
  if (key === "certification.evidence_submitted") return "evidence:submit";
  if (["ci.status", "repo.state_changed", "pr.updated", "review.updated", "testing.result"].includes(key)) {
    return "evidence:submit";
  }
  if (key === "notification.created") return "mission:write";
  return null;
}

export function readPermission(event) {
  if (event.namespace === "agent") return "agent:read";
  if (event.namespace === "certification") return "evidence:read";
  if (["ci", "repo", "pr", "review", "testing"].includes(event.namespace)) return "evidence:read";
  return "mission:read";
}

function authorizedLegacyEvent(user, event, mode) {
  const permission = writePermission(event);
  if (!permission || !allows(user, permission)) return false;
  if (mode === "required" && event.tenant_id !== user.tenant_id) return false;
  return true;
}

class Bucket {
  constructor(limit = 120, windowMs = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.map = new Map();
  }

  take(key) {
    const now = Date.now();
    let state = this.map.get(key);
    if (!state || now - state.start >= this.windowMs) state = { start: now, n: 0 };
    state.n += 1;
    this.map.set(key, state);
    return state.n <= this.limit;
  }
}

const readBody = (req, maxBytes) =>
  new Promise((resolve, reject) => {
    let body = "";
    let size = 0;
    let rejected = false;
    req.on("data", chunk => {
      if (rejected) return;
      size += chunk.length;
      if (size > maxBytes) {
        rejected = true;
        reject(Object.assign(new Error("payload_too_large"), { status: 413 }));
        return;
      }
      body += chunk;
    });
    req.on("end", () => {
      if (rejected) return;
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(Object.assign(new Error("invalid_json"), { status: 400 }));
      }
    });
    req.on("error", reject);
  });

const validChannelName = name =>
  typeof name === "string" &&
  name.length >= 1 &&
  name.length <= 255 &&
  /^[a-zA-Z0-9._\-/:]+$/.test(name);

const API_KEY_PERMISSIONS = new Set([
  "channel:create",
  "channel:read",
  "channel:publish",
  "channel:subscribe",
  "event:publish",
  "event:read",
  "room:create",
  "room:join",
  "stream:create",
  "stream:publish",
  "stream:view",
  "media:publish",
  "media:view",
  "admin:read",
  "admin:write",
]);

const validApiKeyPermissions = permissions =>
  Array.isArray(permissions) &&
  permissions.length > 0 &&
  permissions.length <= 100 &&
  permissions.every(
    permission =>
      typeof permission === "string" &&
      (permission === "*" || API_KEY_PERMISSIONS.has(permission)),
  );

const validCanonicalInput = input =>
  !!input &&
  validChannelName(input.channel) &&
  typeof input.type === "string" &&
  input.type.length > 0 &&
  input.type.length <= 128 &&
  input.data !== undefined &&
  (!input.correlation_id || UUID.test(input.correlation_id)) &&
  (!input.causation_id || UUID.test(input.causation_id)) &&
  (!input.trace_id || typeof input.trace_id === "string");

export function createGateway({
  env = process.env,
  eventStore: providedEventStore,
  broker: providedBroker,
} = {}) {
  let activeSha = env.REALTIME_BUILD_SHA || env.MISSION_CONTROL_BUILD_SHA || "";
  if (!activeSha) {
    try {
      activeSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    } catch {
      activeSha = "0".repeat(40);
    }
  }

  const eventStore =
    providedEventStore ||
    new MemoryEventStore({
      retentionEvents: Number(env.REALTIME_MEMORY_RETENTION_EVENTS || 1000),
    });
  const broker = providedBroker || new MemoryBroker();
  const authenticate = createAuthenticator({ env, eventStore });
  const httpRate = new Bucket(
    Number(env.REALTIME_HTTP_RATE_LIMIT || env.MISSION_CONTROL_EVENT_RATE_LIMIT || 120),
  );
  const wsRate = new Bucket(
    Number(env.REALTIME_WS_RATE_LIMIT || env.MISSION_CONTROL_WS_RATE_LIMIT || 240),
  );
  const legacySequence = new Map();
  const brokerSubscriptions = new Map();

  const acceptLegacySequence = event => {
    const key =
      (event.tenant_id || "local") +
      ":" +
      event.source_service +
      ":" +
      event.namespace;
    const last = legacySequence.get(key) || 0;
    if (event.sequence_no <= last) return false;
    legacySequence.set(key, event.sequence_no);
    return true;
  };

  const authorizeChannel = (user, channel, permission) => {
    if (!allows(user, permission) || !validChannelName(channel)) return false;
    if (channel.startsWith("public/")) return true;
    return channel.startsWith("tenant/" + user.tenant_id + "/") || authMode(env) === "disabled";
  };

  const broadcastCanonical = event => {
    const encoded = JSON.stringify({ op: "event", event });
    for (const client of wss.clients) {
      if (client.readyState !== 1 || !client.subscriptions?.has(event.channel)) continue;
      if (!authorizeChannel(client.user, event.channel, "channel:subscribe")) continue;
      if (client.bufferedAmount > Number(env.REALTIME_WS_BACKPRESSURE_BYTES || 1048576)) {
        client.close(1013, "backpressure");
        continue;
      }
      client.send(encoded);
    }
  };

  const broadcastLegacy = event => {
    const encoded = JSON.stringify(event);
    for (const client of wss.clients) {
      if (client.readyState !== 1) continue;
      if (authMode(env) === "required" && client.user?.tenant_id !== event.tenant_id) continue;
      if (!allows(client.user, readPermission(event))) continue;
      if (client.bufferedAmount > Number(env.REALTIME_WS_BACKPRESSURE_BYTES || 1048576)) {
        client.close(1013, "backpressure");
        continue;
      }
      client.send(encoded);
    }
  };

  const retainBrokerSubscription = async channel => {
    const current = brokerSubscriptions.get(channel);
    if (current) {
      current.refs += 1;
      return;
    }
    const unsubscribe = await broker.subscribe(channel, async event => {
      broadcastCanonical(event);
    });
    brokerSubscriptions.set(channel, { refs: 1, unsubscribe });
  };

  const releaseBrokerSubscription = async channel => {
    const current = brokerSubscriptions.get(channel);
    if (!current) return;
    current.refs -= 1;
    if (current.refs > 0) return;
    brokerSubscriptions.delete(channel);
    await current.unsubscribe();
  };

  const publishCanonical = async (input, user) => {
    if (!validCanonicalInput(input)) {
      const error = new Error("invalid_event");
      error.code = "invalid_event";
      throw error;
    }
    const channel = await eventStore.getChannel(input.channel);
    if (!channel) {
      const error = new Error("channel_not_found");
      error.code = "channel_not_found";
      throw error;
    }
    const event = await eventStore.appendEvent({
      channel: input.channel,
      type: input.type,
      data: input,
      principal: user,
    });
    await broker.publish(event.channel, event);
    return event;
  };

  const issueApiKey = async ({ owner, tenantId, permissions, expiresAt = null }) => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const material = generateApiKey(env.REALTIME_API_KEY_ENVIRONMENT || "live");
      try {
        const metadata = await eventStore.createApiKey({
          id: material.id,
          hash: material.hash,
          prefix: material.prefix,
          owner,
          tenantId,
          permissions,
          expiresAt,
        });
        return { ...metadata, api_key: material.token };
      } catch (error) {
        if (error.code !== "23505" && error.message !== "api_key_exists") throw error;
      }
    }
    throw new Error("api_key_generation_failed");
  };

  const server = http.createServer(async (req, res) => {
    const requestId = String(req.headers["x-request-id"] || crypto.randomUUID());
    const url = new URL(req.url || "/", "http://localhost");
    const path = url.pathname;

    if (path === "/health/live" || path === "/healthz") {
      return sendJson(
        res,
        200,
        {
          ok: true,
          service: "codestra-realtime",
          version: "2.0.0",
          build_sha: activeSha,
          auth_mode: authMode(env),
        },
        requestId,
      );
    }

    if (path === "/health/ready") {
      const [brokerHealth, persistenceHealth] = await Promise.all([
        broker.health(),
        eventStore.health(),
      ]);
      const ready = Boolean(brokerHealth.ok && persistenceHealth.ok);
      return sendJson(
        res,
        ready ? 200 : 503,
        {
          ok: ready,
          ready,
          dependencies: {
            broker: brokerHealth,
            persistence: persistenceHealth,
          },
        },
        requestId,
      );
    }

    if (path === "/v1/system/info") {
      return sendJson(
        res,
        200,
        {
          service: "codestra-realtime",
          version: "2.0.0",
          build_sha: activeSha,
          protocol: REALTIME_PROTOCOL,
          node_id: env.REALTIME_NODE_ID || null,
        },
        requestId,
      );
    }

    if (path === "/v1/system/version") {
      return sendJson(res, 200, { version: "2.0.0", build_sha: activeSha }, requestId);
    }

    if (path === "/v1/system/capabilities") {
      return sendJson(
        res,
        200,
        {
          service: "codestra-realtime",
          version: "2.0.0",
          build_sha: activeSha,
          capabilities: {
            websocket: true,
            events: true,
            channels: true,
            presence: true,
            applications: true,
            connections: true,
            replay: true,
            durable_replay: Boolean(eventStore.durable),
            multi_node_fanout: Boolean(broker.durable),
            rooms: true,
            webrtc: false,
            recording: false,
            broker: broker.kind,
            persistence: eventStore.kind,
          },
        },
        requestId,
      );
    }

    let user;
    try {
      user = await authenticate(extractToken(req));
    } catch {
      return sendError(res, 401, "unauthorized", "Authentication failed.", requestId);
    }

    const ip = req.socket.remoteAddress || "unknown";
    if (!httpRate.take(ip)) {
      return sendError(res, 429, "rate_limited", "Too many requests.", requestId);
    }

    if (path === "/v1/applications" && req.method === "GET") {
      if (!allows(user, "admin:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const items = await eventStore.listApplications(user.tenant_id);
      return sendJson(res, 200, { items }, requestId);
    }

    if (path === "/v1/applications" && req.method === "POST") {
      if (!allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(
          res,
          error.status || 400,
          error.message,
          error.message === "invalid_json" ? "Invalid JSON." : "Request body is too large.",
          requestId,
        );
      }
      if (typeof body.name !== "string" || !body.name.trim() || body.name.length > 128) {
        return sendError(res, 422, "invalid_application", "Application name is invalid.", requestId);
      }
      const permissions = body.permissions === undefined ? [] : body.permissions;
      if (
        !Array.isArray(permissions) ||
        permissions.length > 100 ||
        !permissions.every(
          permission =>
            typeof permission === "string" &&
            (permission === "*" || API_KEY_PERMISSIONS.has(permission)),
        )
      ) {
        return sendError(
          res,
          422,
          "invalid_permissions",
          "Application permissions are invalid.",
          requestId,
        );
      }
      const allowedOrigins = body.allowed_origins === undefined ? [] : body.allowed_origins;
      if (
        !Array.isArray(allowedOrigins) ||
        allowedOrigins.length > 100 ||
        !allowedOrigins.every(origin => typeof origin === "string" && origin.length <= 512)
      ) {
        return sendError(
          res,
          422,
          "invalid_origins",
          "Application allowed origins are invalid.",
          requestId,
        );
      }
      const rateLimits =
        body.rate_limits && typeof body.rate_limits === "object" && !Array.isArray(body.rate_limits)
          ? body.rate_limits
          : {};
      const applicationId = "app_" + crypto.randomBytes(12).toString("hex");
      try {
        const application = await eventStore.createApplication({
          applicationId,
          name: body.name.trim(),
          tenantId: user.tenant_id,
          permissions: [...new Set(permissions)],
          rateLimits,
          allowedOrigins: [...new Set(allowedOrigins)],
        });
        return sendJson(res, 201, application, requestId);
      } catch {
        return sendError(
          res,
          503,
          "persistence_unavailable",
          "Application persistence is unavailable.",
          requestId,
        );
      }
    }

    const applicationMatch = path.match(/^\/v1\/applications\/(app_[a-f0-9]{24})$/);
    if (applicationMatch && req.method === "GET") {
      if (!allows(user, "admin:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const application = await eventStore.getApplication(applicationMatch[1], user.tenant_id);
      if (!application) {
        return sendError(res, 404, "not_found", "Application not found.", requestId);
      }
      return sendJson(res, 200, application, requestId);
    }

    if (path === "/v1/connections" && req.method === "GET") {
      if (!allows(user, "admin:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const activeOnly = url.searchParams.get("active") === "true";
      const items = await eventStore.listConnections(user.tenant_id, { activeOnly });
      return sendJson(res, 200, { items }, requestId);
    }

    const connectionMatch = path.match(/^\/v1\/connections\/([0-9a-f-]{36})$/i);
    if (connectionMatch && req.method === "GET") {
      if (!allows(user, "admin:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const connection = await eventStore.getConnection(connectionMatch[1], user.tenant_id);
      if (!connection) {
        return sendError(res, 404, "not_found", "Connection not found.", requestId);
      }
      return sendJson(res, 200, connection, requestId);
    }

    if (connectionMatch && req.method === "DELETE") {
      if (!allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const connection = await eventStore.getConnection(connectionMatch[1], user.tenant_id);
      if (!connection) {
        return sendError(res, 404, "not_found", "Connection not found.", requestId);
      }
      for (const client of wss.clients) {
        if (client.connectionId === connection.connection_id) {
          client.close(1008, "connection_terminated");
        }
      }
      await eventStore.closeConnection(connection.connection_id);
      res.writeHead(204, { "x-request-id": requestId });
      return res.end();
    }

    const presenceMatch = path.match(/^\/v1\/presence\/(.+)$/);
    if (presenceMatch && req.method === "GET") {
      const channel = decodeURIComponent(presenceMatch[1]);
      if (!authorizeChannel(user, channel, "channel:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const exists = await eventStore.getChannel(channel);
      if (!exists) return sendError(res, 404, "not_found", "Channel not found.", requestId);
      const items = await eventStore.listPresence(channel, user.tenant_id);
      return sendJson(res, 200, { channel, count: items.length, items }, requestId);
    }

    if (path === "/v1/rooms" && req.method === "POST") {
      if (!allows(user, "room:create")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(
          res,
          error.status || 400,
          error.message,
          error.message === "invalid_json" ? "Invalid JSON." : "Request body is too large.",
          requestId,
        );
      }
      const allowedTypes = new Set(["chat", "voice", "video", "collaboration"]);
      if (
        typeof body.name !== "string" ||
        !body.name.trim() ||
        body.name.length > 128 ||
        !allowedTypes.has(body.type)
      ) {
        return sendError(res, 422, "invalid_room", "Room definition is invalid.", requestId);
      }
      const roomId = crypto.randomUUID();
      const channel = `tenant/${user.tenant_id}/rooms/${roomId}`;
      try {
        const room = await eventStore.createRoom({
          roomId,
          tenantId: user.tenant_id,
          name: body.name.trim(),
          type: body.type,
          createdBy: user.sub,
          channel,
        });
        return sendJson(res, 201, room, requestId);
      } catch {
        return sendError(
          res,
          503,
          "persistence_unavailable",
          "Room persistence is unavailable.",
          requestId,
        );
      }
    }

    const roomActionMatch = path.match(
      /^\/v1\/rooms\/([0-9a-f-]{36})\/(join|leave)$/i,
    );
    if (roomActionMatch && req.method === "POST") {
      if (!allows(user, "room:join")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const method = roomActionMatch[2] === "join" ? "joinRoom" : "leaveRoom";
      const room = await eventStore[method](
        roomActionMatch[1],
        user.tenant_id,
        user.sub,
      );
      if (!room) return sendError(res, 404, "not_found", "Room not found.", requestId);
      return sendJson(res, 200, room, requestId);
    }

    const roomMatch = path.match(/^\/v1\/rooms\/([0-9a-f-]{36})$/i);
    if (roomMatch && req.method === "GET") {
      if (!allows(user, "room:join") && !allows(user, "room:create")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const room = await eventStore.getRoom(roomMatch[1], user.tenant_id);
      if (!room) return sendError(res, 404, "not_found", "Room not found.", requestId);
      return sendJson(res, 200, room, requestId);
    }

    if (roomMatch && req.method === "DELETE") {
      if (!allows(user, "room:create") && !allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const deleted = await eventStore.deleteRoom(roomMatch[1], user.tenant_id);
      if (!deleted) return sendError(res, 404, "not_found", "Room not found.", requestId);
      res.writeHead(204, { "x-request-id": requestId });
      return res.end();
    }

    if (path === "/v1/api-keys" && req.method === "GET") {
      if (!allows(user, "admin:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const items = await eventStore.listApiKeys(user.tenant_id);
      return sendJson(res, 200, { items }, requestId);
    }

    if (path === "/v1/api-keys" && req.method === "POST") {
      if (!allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(
          res,
          error.status || 400,
          error.message,
          error.message === "invalid_json" ? "Invalid JSON." : "Request body is too large.",
          requestId,
        );
      }
      if (!validApiKeyPermissions(body.permissions)) {
        return sendError(
          res,
          422,
          "invalid_permissions",
          "API key permissions are invalid.",
          requestId,
        );
      }
      const owner =
        typeof body.owner === "string" && body.owner.length > 0 && body.owner.length <= 128
          ? body.owner
          : user.sub;
      let expiresAt = null;
      if (body.expires_at !== undefined && body.expires_at !== null) {
        const parsed = Date.parse(body.expires_at);
        if (!Number.isFinite(parsed) || parsed <= Date.now()) {
          return sendError(
            res,
            422,
            "invalid_expiration",
            "API key expiration must be in the future.",
            requestId,
          );
        }
        expiresAt = new Date(parsed).toISOString();
      }
      try {
        const issued = await issueApiKey({
          owner,
          tenantId: user.tenant_id,
          permissions: [...new Set(body.permissions)],
          expiresAt,
        });
        return sendJson(res, 201, issued, requestId);
      } catch {
        return sendError(
          res,
          503,
          "persistence_unavailable",
          "API key persistence is unavailable.",
          requestId,
        );
      }
    }

    const rotateApiKeyMatch = path.match(/^\/v1\/api-keys\/([a-f0-9]{16})\/rotate$/);
    if (rotateApiKeyMatch && req.method === "POST") {
      if (!allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const existing = await eventStore.getApiKeyMetadata(rotateApiKeyMatch[1]);
      if (!existing || existing.tenant_id !== user.tenant_id) {
        return sendError(res, 404, "not_found", "API key not found.", requestId);
      }
      if (existing.revoked_at) {
        return sendError(res, 409, "api_key_revoked", "API key is already revoked.", requestId);
      }
      try {
        const issued = await issueApiKey({
          owner: existing.owner,
          tenantId: existing.tenant_id,
          permissions: existing.permissions,
          expiresAt: existing.expires_at,
        });
        await eventStore.revokeApiKey(existing.id, user.tenant_id);
        return sendJson(
          res,
          201,
          { ...issued, rotated_from: existing.id },
          requestId,
        );
      } catch {
        return sendError(
          res,
          503,
          "persistence_unavailable",
          "API key rotation failed.",
          requestId,
        );
      }
    }

    const apiKeyMatch = path.match(/^\/v1\/api-keys\/([a-f0-9]{16})$/);
    if (apiKeyMatch && req.method === "DELETE") {
      if (!allows(user, "admin:write")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const revoked = await eventStore.revokeApiKey(apiKeyMatch[1], user.tenant_id);
      if (!revoked) {
        return sendError(res, 404, "not_found", "API key not found.", requestId);
      }
      res.writeHead(204, { "x-request-id": requestId });
      return res.end();
    }

    if (path === "/v1/channels" && req.method === "GET") {
      if (!allows(user, "channel:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const channels = await eventStore.listChannels();
      return sendJson(
        res,
        200,
        {
          items: channels.filter(channel =>
            authorizeChannel(user, channel.name, "channel:read"),
          ),
        },
        requestId,
      );
    }

    if (path === "/v1/channels" && req.method === "POST") {
      if (!allows(user, "channel:create")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(
          res,
          error.status || 400,
          error.message,
          error.message === "invalid_json" ? "Invalid JSON." : "Request body is too large.",
          requestId,
        );
      }
      if (!validChannelName(body.name) || !authorizeChannel(user, body.name, "channel:create")) {
        return sendError(
          res,
          422,
          "invalid_channel",
          "Channel name is invalid or outside the authenticated tenant.",
          requestId,
        );
      }
      try {
        const channel = await eventStore.createChannel({
          name: body.name,
          tenantId: user.tenant_id,
          retention: body.retention || (eventStore.durable ? "default" : "memory"),
        });
        return sendJson(res, 201, channel, requestId);
      } catch (error) {
        if (error.code === "channel_exists") {
          return sendError(res, 409, "channel_exists", "Channel already exists.", requestId);
        }
        return sendError(res, 503, "persistence_unavailable", "Persistence is unavailable.", requestId);
      }
    }

    const historyMatch = path.match(/^\/v1\/channels\/(.+)\/events$/);
    if (historyMatch && req.method === "GET") {
      const name = decodeURIComponent(historyMatch[1]);
      if (!authorizeChannel(user, name, "event:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const channel = await eventStore.getChannel(name);
      if (!channel) return sendError(res, 404, "not_found", "Channel not found.", requestId);
      const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 100), 1), 500);
      const cursor = Number(url.searchParams.get("cursor") || 0);
      const after = Math.max(Number(url.searchParams.get("after") || 0), cursor);
      const beforeParam = url.searchParams.get("before");
      const before = beforeParam === null ? null : Number(beforeParam);
      const type = url.searchParams.get("type");
      const history = await eventStore.listEvents(name, { after, before, limit, type });
      return sendJson(res, 200, history, requestId);
    }

    const channelMatch = path.match(/^\/v1\/channels\/(.+)$/);
    if (channelMatch && req.method === "GET") {
      const name = decodeURIComponent(channelMatch[1]);
      const channel = await eventStore.getChannel(name);
      if (!channel) return sendError(res, 404, "not_found", "Channel not found.", requestId);
      if (!authorizeChannel(user, name, "channel:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      return sendJson(res, 200, channel, requestId);
    }

    if (channelMatch && req.method === "DELETE") {
      const name = decodeURIComponent(channelMatch[1]);
      if (!authorizeChannel(user, name, "channel:create")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      const deleted = await eventStore.deleteChannel(name);
      if (!deleted) return sendError(res, 404, "not_found", "Channel not found.", requestId);
      res.writeHead(204, { "x-request-id": requestId });
      return res.end();
    }

    if (path === "/v1/events" && req.method === "POST") {
      if (!allows(user, "event:publish")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(
          res,
          error.status || 400,
          error.message,
          error.message === "invalid_json" ? "Invalid JSON." : "Request body is too large.",
          requestId,
        );
      }
      if (!authorizeChannel(user, body.channel, "channel:publish")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      try {
        const event = await publishCanonical(body, user);
        return sendJson(res, 202, event, requestId);
      } catch (error) {
        if (error.code === "invalid_event") {
          return sendError(res, 422, "invalid_event", "Event payload is invalid.", requestId);
        }
        if (error.code === "channel_not_found") {
          return sendError(res, 404, "channel_not_found", "Channel not found.", requestId);
        }
        return sendError(res, 503, "runtime_unavailable", "Realtime runtime is unavailable.", requestId);
      }
    }

    const eventMatch = path.match(/^\/v1\/events\/([0-9a-f-]+)$/i);
    if (eventMatch && req.method === "GET") {
      const event = await eventStore.getEvent(eventMatch[1]);
      if (!event) return sendError(res, 404, "not_found", "Event not found.", requestId);
      if (!authorizeChannel(user, event.channel, "event:read")) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      return sendJson(res, 200, event, requestId);
    }

    if (path === "/events" && req.method === "POST") {
      let body;
      try {
        body = await readBody(req, Number(env.REALTIME_HTTP_BODY_MAX || 1048576));
      } catch (error) {
        return sendError(res, error.status || 400, error.message, "Invalid request.", requestId);
      }
      if (!validEvent(body)) {
        return sendError(res, 422, "invalid_event", "Legacy event payload is invalid.", requestId);
      }
      if (!authorizedLegacyEvent(user, body, authMode(env))) {
        return sendError(res, 403, "forbidden", "Request is not permitted.", requestId);
      }
      if (!acceptLegacySequence(body)) {
        return sendError(res, 409, "replay", "Sequence was already accepted.", requestId);
      }
      broadcastLegacy(body);
      res.writeHead(202, { "x-request-id": requestId });
      return res.end();
    }

    return sendError(res, 404, "not_found", "Route not found.", requestId);
  });

  const wss = new WebSocketServer({
    server,
    maxPayload: Number(env.REALTIME_WS_FRAME_MAX || 1048576),
    verifyClient: (info, cb) => {
      const origin = info.req.headers.origin;
      const allowed = (env.REALTIME_ALLOWED_ORIGINS || "")
        .split(",")
        .map(value => value.trim())
        .filter(Boolean);
      if (origin && allowed.length && !allowed.includes(origin)) {
        return cb(false, 403, "Forbidden");
      }
      authenticate(extractToken(info.req))
        .then(user => {
          info.req.user = user;
          cb(true);
        })
        .catch(() => cb(false, 401, "Unauthorized"));
    },
    handleProtocols: protocols =>
      protocols.has(REALTIME_PROTOCOL)
        ? REALTIME_PROTOCOL
        : protocols.has("mission-control")
          ? "mission-control"
          : false,
  });

  const sendSocket = (socket, payload) => {
    if (socket.readyState !== 1) return false;
    const encoded = JSON.stringify(payload);
    socket.send(encoded);
    if (socket.connectionId) {
      eventStore
        .updateConnection(socket.connectionId, {
          bytesOut: Buffer.byteLength(encoded),
          messagesOut: 1,
        })
        .catch(() => {});
    }
    return true;
  };

  const sendWsError = (socket, code, message) =>
    sendSocket(socket, { op: "error", error: { code, message } });

  wss.on("connection", async (socket, req) => {
    socket.isAlive = true;
    socket.user = req.user;
    socket.subscriptions = new Set();
    socket.connectionId = crypto.randomUUID();

    try {
      await eventStore.openConnection({
        connectionId: socket.connectionId,
        principalId: socket.user.sub,
        applicationId: socket.user.application_id || null,
        tenantId: socket.user.tenant_id,
        nodeId: env.REALTIME_NODE_ID || null,
        remoteAddress: req.socket.remoteAddress || null,
        userAgent: String(req.headers["user-agent"] || "").slice(0, 512) || null,
      });
    } catch {
      socket.close(1011, "connection_persistence_failed");
      return;
    }

    socket.on("pong", () => {
      socket.isAlive = true;
      eventStore.updateConnection(socket.connectionId).catch(() => {});
    });

    sendSocket(socket, {
      op: "connected",
      connection_id: socket.connectionId,
      protocol: socket.protocol || REALTIME_PROTOCOL,
      node_id: env.REALTIME_NODE_ID || null,
    });

    socket.on("message", async raw => {
      eventStore
        .updateConnection(socket.connectionId, {
          bytesIn: raw.length ?? Buffer.byteLength(raw.toString()),
          messagesIn: 1,
        })
        .catch(() => {});

      if (!wsRate.take(socket.user?.sub || req.socket.remoteAddress || "unknown")) {
        return socket.close(1013, "rate_limited");
      }

      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return socket.close(1007, "invalid_json");
      }

      try {
        if (msg?.op === "ping") {
          return sendSocket(socket, { op: "pong", timestamp: new Date().toISOString() });
        }

        if (msg?.op === "subscribe") {
          if (
            !validChannelName(msg.channel) ||
            !authorizeChannel(socket.user, msg.channel, "channel:subscribe")
          ) {
            return sendWsError(socket, "forbidden", "Subscription is not permitted.");
          }
          const channel = await eventStore.getChannel(msg.channel);
          if (!channel) return sendWsError(socket, "channel_not_found", "Channel not found.");
          if (!socket.subscriptions.has(msg.channel)) {
            await retainBrokerSubscription(msg.channel);
            socket.subscriptions.add(msg.channel);
            await eventStore.updateConnection(socket.connectionId, {
              subscriptions: [...socket.subscriptions],
            });
          }
          return sendSocket(socket, { op: "subscribed", channel: msg.channel });
        }

        if (msg?.op === "unsubscribe") {
          if (socket.subscriptions.delete(msg.channel)) {
            await releaseBrokerSubscription(msg.channel);
            await eventStore.updateConnection(socket.connectionId, {
              subscriptions: [...socket.subscriptions],
            });
          }
          return sendSocket(socket, { op: "unsubscribed", channel: msg.channel });
        }

        if (msg?.op === "resume") {
          const after = Number(msg.after || 0);
          if (
            !validChannelName(msg.channel) ||
            !Number.isSafeInteger(after) ||
            after < 0 ||
            !authorizeChannel(socket.user, msg.channel, "channel:subscribe")
          ) {
            return sendWsError(socket, "invalid_resume", "Resume request is invalid.");
          }
          const channel = await eventStore.getChannel(msg.channel);
          if (!channel) return sendWsError(socket, "channel_not_found", "Channel not found.");
          if (!socket.subscriptions.has(msg.channel)) {
            await retainBrokerSubscription(msg.channel);
            socket.subscriptions.add(msg.channel);
            await eventStore.updateConnection(socket.connectionId, {
              subscriptions: [...socket.subscriptions],
            });
          }
          const replay = await eventStore.listEvents(msg.channel, {
            after,
            limit: Math.min(Number(env.REALTIME_REPLAY_MAX_EVENTS || 1000), 5000),
          });
          for (const event of replay.items) {
            sendSocket(socket, { op: "event", event, replay: true });
          }
          return sendSocket(socket, {
            op: "resumed",
            channel: msg.channel,
            after,
            replayed: replay.items.length,
            next_cursor: replay.next_cursor,
          });
        }

        if (msg?.op === "ack") {
          if (!UUID.test(msg.event_id || "")) {
            return sendWsError(socket, "invalid_ack", "Acknowledgement is invalid.");
          }
          await broker.ack(msg.event_id);
          return sendSocket(socket, { op: "acked", event_id: msg.event_id });
        }

        if (msg?.op === "publish") {
          if (!authorizeChannel(socket.user, msg.channel, "channel:publish")) {
            return sendWsError(socket, "forbidden", "Publish is not permitted.");
          }
          try {
            const event = await publishCanonical(
              {
                channel: msg.channel,
                type: msg.type,
                data: msg.data,
                correlation_id: msg.correlation_id,
                causation_id: msg.causation_id,
                trace_id: msg.trace_id,
              },
              socket.user,
            );
            return sendSocket(socket, {
              op: "published",
              event_id: event.id,
              sequence: event.sequence,
            });
          } catch (error) {
            if (error.code === "channel_not_found") {
              return sendWsError(socket, "channel_not_found", "Channel not found.");
            }
            if (error.code === "invalid_event") {
              return sendWsError(socket, "invalid_event", "Event payload is invalid.");
            }
            return sendWsError(socket, "runtime_unavailable", "Realtime runtime is unavailable.");
          }
        }

        if (validEvent(msg)) {
          if (!authorizedLegacyEvent(socket.user, msg, authMode(env))) {
            return socket.close(1008, "forbidden");
          }
          if (!acceptLegacySequence(msg)) return socket.close(1008, "replay");
          broadcastLegacy(msg);
          return;
        }

        socket.close(1007, "invalid_frame");
      } catch {
        sendWsError(socket, "runtime_unavailable", "Realtime runtime is unavailable.");
      }
    });

    socket.on("close", () => {
      for (const channel of [...socket.subscriptions]) {
        releaseBrokerSubscription(channel).catch(() => {});
      }
      socket.subscriptions.clear();
      eventStore.closeConnection(socket.connectionId).catch(() => {});
    });
  });

  const timer = setInterval(() => {
    for (const socket of wss.clients) {
      if (!socket.isAlive) {
        socket.terminate();
        continue;
      }
      socket.isAlive = false;
      socket.ping();
    }
  }, Number(env.REALTIME_HEARTBEAT_MS || 30000));
  timer.unref();

  const shutdown = async () => {
    clearInterval(timer);
    for (const socket of wss.clients) {
      try {
        socket.send(JSON.stringify({ op: "server.shutdown" }));
      } catch {}
      socket.close(1012, "server_restart");
    }
    for (const entry of brokerSubscriptions.values()) {
      await entry.unsubscribe().catch(() => {});
    }
    brokerSubscriptions.clear();
    await new Promise(resolve => {
      if (!server.listening) return resolve();
      server.close(() => resolve());
    });
  };

  return {
    server,
    wss,
    broadcast: broadcastCanonical,
    eventStore,
    broker,
    shutdown,
  };
}

export function assertSafeBind(env = process.env, host = env.HOST || "127.0.0.1") {
  if (
    authMode(env) === "disabled" &&
    !["127.0.0.1", "::1", "localhost"].includes(host)
  ) {
    throw new Error("AUTH_MODE=disabled may only bind to loopback");
  }
  return host;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const env = process.env;
  const host = assertSafeBind(env);
  const runtime = await createRuntime(env);
  const gateway = createGateway({ env, ...runtime });
  gateway.server.listen(Number(env.PORT || 8787), host, () => {
    console.log(
      `codestra-realtime ready on ${host}:${env.PORT || 8787} (${runtime.eventStore.kind}/${runtime.broker.kind})`,
    );
  });

  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await gateway.shutdown();
    await runtime.close();
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
}
