import http from "node:http";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { WebSocketServer } from "ws";

export const allowedNamespaces=new Set(["agent","mission","ci","repo","notification","pr","review","testing","certification"]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{40}$/;
const states=new Set(["QUEUED","ASSIGNED","LEASED","STARTING","ACTIVE","TESTING","CHECKPOINTED","IN_REVIEW","CERTIFICATION","COMPLETED","BLOCKED","STALLED","STOPPED","FAILED"]);
const roles={
 Administrator:new Set(["*"]),
 Operator:new Set(["mission:read","mission:write","agent:assign","agent:stop","router:lease"]),
 Reviewer:new Set(["mission:read","evidence:read","evidence:certify","review:approve","pr:link","agent:read"]),
 Viewer:new Set(["mission:read","evidence:read","agent:read"]),
 Agent:new Set(["agent:heartbeat","agent:checkpoint","evidence:submit","task:claim"])
};

const b64=s=>Buffer.from(s.replace(/-/g,"+").replace(/_/g,"/"),"base64");
const jsonPart=s=>JSON.parse(b64(s).toString("utf8"));
const allows=(user,permission)=>user.roles.some(r=>roles.get?.(r)?.has(permission)||roles[r]?.has("*")||roles[r]?.has(permission));
const extractToken=req=>{
 const auth=req.headers.authorization||"";if(auth.startsWith("Bearer "))return auth.slice(7).trim();
 const protocols=String(req.headers["sec-websocket-protocol"]||"").split(",").map(x=>x.trim());
 const bearer=protocols.find(x=>x.startsWith("bearer."));return bearer?bearer.slice(7):null;
};

export function createJwtVerifier(env=process.env){
 const mode=(env.MISSION_CONTROL_AUTH_MODE||"disabled").toLowerCase();
 const issuer=(env.MISSION_CONTROL_JWT_ISSUER||"").replace(/\/$/,"");
 const audience=env.MISSION_CONTROL_JWT_AUDIENCE||"websocket-gateway";
 const allowedAzp=new Set((env.MISSION_CONTROL_ALLOWED_AZP||"mission-control-ui,mission-control-backend").split(",").filter(Boolean));
 let jwks={expires:0,keys:new Map()};
 if(mode==="required"&&!issuer)throw new Error("MISSION_CONTROL_JWT_ISSUER required");
 async function keyFor(kid){
  if(Date.now()>jwks.expires||!jwks.keys.has(kid)){
   const res=await fetch(issuer+"/protocol/openid-connect/certs");if(!res.ok)throw new Error("jwks_unavailable");
   const body=await res.json();jwks={expires:Date.now()+300000,keys:new Map((body.keys||[]).map(k=>[k.kid,k]))};
  }
  const jwk=jwks.keys.get(kid);if(!jwk)throw new Error("unknown_kid");return crypto.createPublicKey({key:jwk,format:"jwk"});
 }
 return async token=>{
  if(mode==="disabled")return {sub:"local-development",roles:["Administrator"]};
  if(!token)throw new Error("missing_bearer_token");
  const parts=token.split(".");if(parts.length!==3)throw new Error("invalid_token");
  const header=jsonPart(parts[0]),claims=jsonPart(parts[1]);if(header.alg!=="RS256")throw new Error("invalid_alg");
  const key=await keyFor(header.kid);const ok=crypto.verify("RSA-SHA256",Buffer.from(parts[0]+"."+parts[1]),key,b64(parts[2]));if(!ok)throw new Error("invalid_signature");
  const now=Math.floor(Date.now()/1000);if(claims.iss!==issuer||!claims.exp||claims.exp<=now||!claims.iat)throw new Error("invalid_claims");
  const aud=Array.isArray(claims.aud)?claims.aud:[claims.aud];if(!aud.includes(audience))throw new Error("invalid_audience");
  if(allowedAzp.size&&!allowedAzp.has(claims.azp))throw new Error("invalid_azp");
  const rr=claims.realm_access?.roles||[],cr=claims.resource_access?.["mission-control"]?.roles||[];
  return {sub:claims.sub,roles:[...new Set([...rr,...cr])],claims};
 };
}

function validPayload(event){
 if(event.namespace==="agent"&&event.event_type==="heartbeat"){
  const p=event.payload;return !!p&&typeof p.agent_id==="string"&&typeof p.task_id==="string"&&SHA.test(p.current_sha||"")&&states.has(p.status)&&Number.isInteger(p.changed_files_count)&&p.changed_files_count>=0;
 }
 if(event.namespace==="mission"&&event.event_type==="state_transition"){
  const p=event.payload;return !!p&&typeof p.task_id==="string"&&typeof p.previous_state==="string"&&states.has(p.new_state)&&SHA.test(p.target_sha||"")&&typeof p.triggered_by==="string";
 }
 if(event.namespace==="certification"&&event.event_type==="evidence_submitted"){
  const p=event.payload;return !!p&&UUID.test(p.certification_id||"")&&typeof p.task_id==="string"&&SHA.test(p.exact_sha||"")&&typeof p.test_pass_rate==="number"&&p.test_pass_rate>=0&&p.test_pass_rate<=100&&typeof p.artifact_url==="string";
 }
 return true;
}

export function validEvent(event){
 return !!event&&typeof event==="object"&&UUID.test(event.event_id||"")&&Number.isInteger(event.sequence_no)&&event.sequence_no>=1&&allowedNamespaces.has(event.namespace)&&typeof event.event_type==="string"&&event.event_type.length>0&&typeof event.timestamp==="string"&&!Number.isNaN(Date.parse(event.timestamp))&&typeof event.source_service==="string"&&event.source_service.length>0&&event.payload&&typeof event.payload==="object"&&!Array.isArray(event.payload)&&(!event.correlation_id||UUID.test(event.correlation_id))&&(!event.causation_id||UUID.test(event.causation_id))&&validPayload(event);
}

class Bucket{
 constructor(limit=120,windowMs=60000){this.limit=limit;this.windowMs=windowMs;this.map=new Map()}
 take(key){const now=Date.now();let x=this.map.get(key);if(!x||now-x.start>=this.windowMs)x={start:now,n:0};x.n++;this.map.set(key,x);return x.n<=this.limit}
}

export function createGateway({env=process.env}={}){
 let activeSha=env.MISSION_CONTROL_BUILD_SHA||"0".repeat(40);try{activeSha=execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim()}catch{}
 const verifyJwt=createJwtVerifier(env),httpRate=new Bucket(Number(env.MISSION_CONTROL_EVENT_RATE_LIMIT||120)),wsRate=new Bucket(Number(env.MISSION_CONTROL_WS_RATE_LIMIT||240));
 const lastSequence=new Map();
 const server=http.createServer(async(req,res)=>{
  if(req.url==="/healthz"){res.writeHead(200,{"content-type":"application/json"});return res.end(JSON.stringify({ok:true,service:"mission-control-realtime",active_sha:activeSha,auth_mode:env.MISSION_CONTROL_AUTH_MODE||"disabled"}));}
  if(req.url==="/events"&&req.method==="POST"){
   let user;try{user=await verifyJwt(extractToken(req));if(!allows(user,"evidence:submit")&&!allows(user,"mission:write"))throw new Error("forbidden");}catch(e){res.writeHead(e.message==="forbidden"?403:401);return res.end();}
   const ip=req.socket.remoteAddress||"unknown";if(!httpRate.take(ip)){res.writeHead(429);return res.end();}
   let body="",oversized=false;req.on("data",c=>{body+=c;if(Buffer.byteLength(body)>1048576){oversized=true;req.destroy();}});
   req.on("end",()=>{if(oversized)return;let event;try{event=JSON.parse(body);}catch{res.writeHead(400);return res.end();}if(!validEvent(event)){res.writeHead(422);return res.end();}
    const key=event.source_service+":"+event.namespace,last=lastSequence.get(key)||0;if(event.sequence_no<=last){res.writeHead(409);return res.end();}lastSequence.set(key,event.sequence_no);broadcast(event);res.writeHead(202);res.end();});return;
  }
  res.writeHead(404);res.end();
 });
 const wss=new WebSocketServer({server,maxPayload:1048576,verifyClient:(info,cb)=>{verifyJwt(extractToken(info.req)).then(u=>{if(!allows(u,"mission:read")&&!allows(u,"agent:read"))return cb(false,403,"Forbidden");info.req.user=u;cb(true)}).catch(()=>cb(false,401,"Unauthorized"));},handleProtocols:protocols=>protocols.has("mission-control")?"mission-control":false});
 const broadcast=event=>{const encoded=JSON.stringify(event);for(const client of wss.clients){if(client.readyState!==1)continue;if(client.bufferedAmount>1048576){client.close(1013,"backpressure");continue;}client.send(encoded);}};
 wss.on("connection",(socket,req)=>{socket.isAlive=true;socket.user=req.user;socket.on("pong",()=>socket.isAlive=true);socket.on("message",raw=>{if(!wsRate.take(socket.user?.sub||req.socket.remoteAddress||"unknown"))return socket.close(1013,"rate_limited");let event;try{event=JSON.parse(raw.toString());}catch{return socket.close(1007,"invalid_json");}if(!validEvent(event))return socket.close(1007,"invalid_event");if(!allows(socket.user,"evidence:submit")&&!allows(socket.user,"mission:write"))return socket.close(1008,"forbidden");broadcast(event);});});
 const timer=setInterval(()=>{for(const socket of wss.clients){if(!socket.isAlive){socket.terminate();continue;}socket.isAlive=false;socket.ping();}},30000);timer.unref();
 return {server,wss,broadcast};
}
if(process.argv[1]===new URL(import.meta.url).pathname){const {server}=createGateway();server.listen(Number(process.env.PORT||8787),"127.0.0.1",()=>console.log("realtime-gateway ready"));}
