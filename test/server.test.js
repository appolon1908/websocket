import test from "node:test";
import assert from "node:assert/strict";
import {validEvent} from "../src/server.js";
test("accepts governed namespaces",()=>{assert.equal(validEvent({type:"agent.heartbeat",ts:new Date().toISOString(),payload:{agent_id:"codex-1"}}),true);assert.equal(validEvent({type:"crypto.tick",ts:new Date().toISOString(),payload:{symbol:"BTC-USD"}}),true);});
test("rejects unknown namespace",()=>assert.equal(validEvent({type:"random",ts:new Date().toISOString(),payload:{}}),false));
