import crypto from "node:crypto";

const KEY_RE = /^rt_(live|test|local)_([a-f0-9]{16})_([A-Za-z0-9_-]{32,})$/;

export function hashApiKey(token) {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

export function generateApiKey(environment = "live") {
  if (!["live", "test", "local"].includes(environment)) {
    throw new Error("invalid_api_key_environment");
  }
  const id = crypto.randomBytes(8).toString("hex");
  const secret = crypto.randomBytes(32).toString("base64url");
  const token = `rt_${environment}_${id}_${secret}`;
  return {
    id,
    token,
    prefix: `rt_${environment}_${id}`,
    hash: hashApiKey(token),
  };
}

export function parseApiKey(token) {
  if (typeof token !== "string") return null;
  const match = token.match(KEY_RE);
  if (!match) return null;
  return {
    environment: match[1],
    id: match[2],
  };
}

export function safeTokenEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export async function authenticateApiKey({ token, eventStore, env = process.env }) {
  const bootstrap = env.REALTIME_BOOTSTRAP_API_KEY || "";
  if (bootstrap && safeTokenEqual(token, bootstrap)) {
    return {
      sub: "bootstrap-admin",
      roles: [],
      permissions: ["*"],
      tenant_id: env.REALTIME_BOOTSTRAP_TENANT || "local",
      application_id: "bootstrap",
    };
  }

  const parsed = parseApiKey(token);
  if (!parsed) throw new Error("invalid_api_key");

  const record = await eventStore.getApiKeyAuthRecord(parsed.id);
  if (!record) throw new Error("invalid_api_key");
  if (!safeTokenEqual(hashApiKey(token), record.key_hash)) throw new Error("invalid_api_key");
  if (record.revoked_at) throw new Error("api_key_revoked");
  if (record.expires_at && new Date(record.expires_at).getTime() <= Date.now()) {
    throw new Error("api_key_expired");
  }

  await eventStore.touchApiKey(parsed.id);
  return {
    sub: `api-key:${parsed.id}`,
    roles: [],
    permissions: record.permissions || [],
    tenant_id: record.tenant_id,
    application_id: record.owner || `api-key:${parsed.id}`,
    api_key_id: parsed.id,
  };
}
