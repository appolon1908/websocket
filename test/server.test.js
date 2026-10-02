import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {WebSocket} from "ws";
import {createGateway,validEvent,REALTIME_PROTOCOL,assertSafeBind} from "../src/server.js";

const base=(over={})=>({event_id:crypto.randomUUID(),sequence_no:1,namespace:"mission",event_type:"state_transition",timestamp:new Date().toISOString(),source_service:"test",payload:{task_id:"T1",previous_state:"ACTIVE",new_state:"TESTING",target_sha:"a".repeat(40),triggered_by:"tester"},...over});
async function withServer(fn){const {server}=createGateway({env:{REALTIME_AUTH_MODE:"disabled"}});await new Promise(r=>server.listen(0,"127.0.0.1",r));try{return await fn(server.address().port);}finally{await new Promise(r=>server.close(r));}}
test("accepts strict governed envelope",()=>assert.equal(validEvent(base()),true));
test("rejects legacy and unknown namespace",()=>{assert.equal(validEvent({type:"mission.x",ts:new Date().toISOString(),payload:{}}),false);assert.equal(validEvent(base({namespace:"evil"})),false)});
test("validates heartbeat payload",()=>assert.equal(validEvent(base({namespace:"agent",event_type:"heartbeat",payload:{agent_id:"A",task_id:"T",current_sha:"b".repeat(40),status:"ACTIVE",changed_files_count:0}})),true));

test("canonical health and system endpoints expose standalone contract",()=>withServer(async port=>{
 const live=await fetch(`http://127.0.0.1:${port}/health/live`);assert.equal(live.status,200);assert.equal(live.headers.has("x-request-id"),true);
 const ready=await (await fetch(`http://127.0.0.1:${port}/health/ready`)).json();assert.equal(ready.ready,true);
 const caps=await (await fetch(`http://127.0.0.1:${port}/v1/system/capabilities`)).json();assert.equal(caps.service,"codestra-realtime");assert.equal(caps.capabilities.websocket,true);assert.equal(caps.capabilities.broker,"memory");
}));

test("channel CRUD and HTTP event delivery/history work through v1",()=>withServer(async port=>{
 const channel="tenant/local/orders";
 let res=await fetch(`http://127.0.0.1:${port}/v1/channels`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:channel})});assert.equal(res.status,201);
 res=await fetch(`http://127.0.0.1:${port}/v1/events`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({channel,type:"order.updated",data:{order_id:"ORD-500"}})});assert.equal(res.status,202);const event=await res.json();assert.equal(event.sequence,1);assert.equal(event.channel,channel);assert.equal(event.tenant_id,"local");assert.match(event.id,/^[0-9a-f-]{36}$/);
 const fetched=await (await fetch(`http://127.0.0.1:${port}/v1/events/${event.id}`)).json();assert.equal(fetched.type,"order.updated");
 const history=await (await fetch(`http://127.0.0.1:${port}/v1/channels/${encodeURIComponent(channel)}/events?after=0&limit=10`)).json();assert.equal(history.items.length,1);assert.equal(history.items[0].id,event.id);
}));

test("websocket canonical protocol subscribes and receives published event",()=>withServer(async port=>{
 const channel="tenant/local/chat/support";
 await fetch(`http://127.0.0.1:${port}/v1/channels`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:channel})});
 const ws=new WebSocket(`ws://127.0.0.1:${port}/ws`,REALTIME_PROTOCOL);
 const received=[];
 ws.on("message",d=>received.push(JSON.parse(d.toString())));
 await new Promise((resolve,reject)=>{ws.once("open",resolve);ws.once("error",reject)});
 ws.send(JSON.stringify({op:"subscribe",channel}));
 await new Promise(r=>setTimeout(r,20));
 ws.send(JSON.stringify({op:"publish",channel,type:"chat.message",data:{text:"hello"}}));
 await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(new Error("event timeout")),500);const poll=setInterval(()=>{if(received.some(x=>x.op==="event")){clearTimeout(t);clearInterval(poll);resolve();}},5);});
 const event=received.find(x=>x.op==="event").event;assert.equal(event.data.text,"hello");assert.equal(event.sequence,1);ws.close();
}));

test("legacy http ingest remains compatible and rejects replay",()=>withServer(async port=>{const e=base();let res=await fetch(`http://127.0.0.1:${port}/events`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(e)});assert.equal(res.status,202);res=await fetch(`http://127.0.0.1:${port}/events`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(e)});assert.equal(res.status,409);}));
test("legacy health remains compatible",()=>withServer(async port=>{const x=await (await fetch(`http://127.0.0.1:${port}/healthz`)).json();assert.equal(x.ok,true);assert.equal(x.auth_mode,"disabled");}));
test("rejects unknown governed event type and invalid previous state",()=>{assert.equal(validEvent(base({event_type:"typo",payload:{x:1}})),false);assert.equal(validEvent(base({payload:{task_id:"T1",previous_state:"garbage",new_state:"TESTING",target_sha:"a".repeat(40),triggered_by:"tester"}})),false);});
test("maps event permissions by type",async()=>{const {writePermission,readPermission}=await import("../src/server.js");assert.equal(writePermission(base()),"mission:write");assert.equal(writePermission(base({namespace:"certification",event_type:"evidence_submitted",payload:{certification_id:crypto.randomUUID(),task_id:"T",exact_sha:"a".repeat(40),test_pass_rate:100,artifact_url:"https://example.test/a"}})),"evidence:submit");assert.equal(readPermission(base({namespace:"agent",event_type:"heartbeat",payload:{agent_id:"A",task_id:"T",current_sha:"a".repeat(40),status:"ACTIVE",changed_files_count:0}})),"agent:read");});
test("auth disabled refuses non-loopback public bind",()=>{assert.throws(()=>assertSafeBind({REALTIME_AUTH_MODE:"disabled"},"0.0.0.0"),/loopback/);assert.equal(assertSafeBind({REALTIME_AUTH_MODE:"disabled"},"127.0.0.1"),"127.0.0.1");});
