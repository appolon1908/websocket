import fs from "node:fs/promises";
import { PUBLIC_HTTP_ROUTES } from "../src/http-contract.js";

const spec = JSON.parse(await fs.readFile("openapi/realtime.v1.yaml", "utf8"));
if (spec.openapi !== "3.1.0") throw new Error("OpenAPI 3.1.0 required");

const methods = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);
const documented = [];
for (const [path, item] of Object.entries(spec.paths || {})) {
  for (const method of Object.keys(item)) {
    if (methods.has(method)) documented.push([method.toUpperCase(), path]);
  }
}
const normalize = routes => routes.map(([method,path]) => `${method} ${path}`).sort();
const expected = normalize(PUBLIC_HTTP_ROUTES);
const actual = normalize(documented);

if (JSON.stringify(expected) !== JSON.stringify(actual)) {
  console.error("EXPECTED", expected);
  console.error("DOCUMENTED", actual);
  throw new Error("openapi_route_parity_failed");
}
console.log(`OPENAPI_PARITY=PASS routes=${actual.length}`);
