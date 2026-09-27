import test from "node:test";import assert from "node:assert/strict";import crypto from "node:crypto";import {createGateway,validEvent} from "../src/server.js";
const base=(over={})=>({event_id:crypto.randomUUID(),sequence_no:1,namespace:"mission",event_type:"state_transition",timestamp:new Date().toISOString(),source_service:"test",payload:{task_id:"T1",previous_state:"ACTIVE",new_state:"TESTING",target_sha:"a".repeat(40),triggered_by:"tester"},...over});
test("accepts strict governed envelope",()=>assert.equal(validEvent(base()),true));
test("rejects legacy and unknown namespace",()=>{assert.equal(validEvent({type:"mission.x",ts:new Date().toISOString(),payload:{}}),false);assert.equal(validEvent(base({namespace:"evil"})),false)});
test("validates heartbeat payload",()=>assert.equal(validEvent(base({namespace:"agent",event_type:"heartbeat",payload:{agent_id:"A",task_id:"T",current_sha:"b".repeat(40),status:"ACTIVE",changed_files_count:0}})),true));
test("http ingest accepts authenticated local-mode event and rejects replay",async()=>{const {server}=createGateway({env:{MISSION_CONTROL_AUTH_MODE:"disabled"}});await new Promise(r=>server.listen(0,"127.0.0.1",r));try{const {port}=server.address(),e=base();let res=await fetch("http://127.0.0.1:"+port+"/events",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(e)});assert.equal(res.status,202);res=await fetch("http://127.0.0.1:"+port+"/events",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(e)});assert.equal(res.status,409);}finally{server.close();}});
test("health exposes auth mode",async()=>{const {server}=createGateway({env:{MISSION_CONTROL_AUTH_MODE:"disabled"}});await new Promise(r=>server.listen(0,"127.0.0.1",r));try{const {port}=server.address();const x=await (await fetch("http://127.0.0.1:"+port+"/healthz")).json();assert.equal(x.ok,true);assert.equal(x.auth_mode,"disabled");}finally{server.close();}});
test("rejects unknown governed event type and invalid previous state",()=>{
 assert.equal(validEvent(base({event_type:'typo',payload:{x:1}})),false);
 assert.equal(validEvent(base({payload:{task_id:'T1',previous_state:'garbage',new_state:'TESTING',target_sha:'a'.repeat(40),triggered_by:'tester'}})),false);
});
test("maps event permissions by type",async()=>{
 const {writePermission,readPermission}=await import('../src/server.js');
 assert.equal(writePermission(base()),'mission:write');
 assert.equal(writePermission(base({namespace:'certification',event_type:'evidence_submitted',payload:{certification_id:crypto.randomUUID(),task_id:'T',exact_sha:'a'.repeat(40),test_pass_rate:100,artifact_url:'https://example.test/a'}})),'evidence:submit');
 assert.equal(readPermission(base({namespace:'agent',event_type:'heartbeat',payload:{agent_id:'A',task_id:'T',current_sha:'a'.repeat(40),status:'ACTIVE',changed_files_count:0}})),'agent:read');
});
