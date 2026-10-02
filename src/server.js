import http from "node:http";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { WebSocketServer } from "ws";

export const REALTIME_PROTOCOL = "codestra.realtime.v1";
export const allowedNamespaces=new Set(["agent","mission","ci","repo","notification","pr","review","testing","certification"]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA=/^[0-9a-f]{40}$/;
const states=new Set(["QUEUED","ASSIGNED","LEASED","STARTING","ACTIVE","TESTING","CHECKPOINTED","IN_REVIEW","CERTIFICATION","COMPLETED","BLOCKED","STALLED","STOPPED","FAILED"]);
const roles={
 Administrator:new Set(["*"]),
 Operator:new Set(["mission:read","mission:write","agent:assign","agent:stop","router:lease","channel:create","channel:read","channel:publish","channel:subscribe","event:publish","event:read"]),
 Reviewer:new Set(["mission:read","evidence:read","evidence:certify","review:approve","pr:link","agent:read","channel:read","channel:subscribe","event:read"]),
 Viewer:new Set(["mission:read","evidence:read","agent:read","channel:read","channel:subscribe","event:read"]),
 Agent:new Set(["agent:heartbeat","agent:checkpoint","evidence:submit","task:claim","channel:publish","channel:subscribe","event:publish"])
};

const b64=s=>Buffer.from(s.replace(/-/g,"+").replace(/_/g,"/"),"base64");
const jsonPart=s=>JSON.parse(b64(s).toString("utf8"));
const allows=(user,permission)=>user.roles.some(r=>roles[r]?.has("*")||roles[r]?.has(permission));
const authMode=env=>(env.REALTIME_AUTH_MODE||env.MISSION_CONTROL_AUTH_MODE||"disabled").toLowerCase();
const extractToken=req=>{
 const auth=req.headers.authorization||"";if(auth.startsWith("Bearer "))return auth.slice(7).trim();
 const protocols=String(req.headers["sec-websocket-protocol"]||"").split(",").map(x=>x.trim());
 const bearer=protocols.find(x=>x.startsWith("bearer."));return bearer?bearer.slice(7):null;
};
const sendJson=(res,status,body,requestId)=>{res.writeHead(status,{"content-type":"application/json","x-request-id":requestId});res.end(JSON.stringify(body));};
const sendError=(res,status,code,message,requestId)=>sendJson(res,status,{error:{code,message,request_id:requestId}},requestId);

export function createJwtVerifier(env=process.env){
 const mode=authMode(env);
 const issuer=(env.REALTIME_JWT_ISSUER||env.MISSION_CONTROL_JWT_ISSUER||"").replace(/\/$/,"");
 const audience=env.REALTIME_JWT_AUDIENCE||env.MISSION_CONTROL_JWT_AUDIENCE||"websocket-gateway";
 const allowedAzp=new Set((env.REALTIME_ALLOWED_AZP||env.MISSION_CONTROL_ALLOWED_AZP||"mission-control-ui,mission-control-backend").split(",").filter(Boolean));
 const tenantClaim=env.REALTIME_TENANT_CLAIM||env.MISSION_CONTROL_TENANT_CLAIM||"tenant_id";
 let jwks={expires:0,keys:new Map()};
 if(mode==="required"&&!issuer)throw new Error("REALTIME_JWT_ISSUER required");
 async function keyFor(kid){
  if(Date.now()>jwks.expires||!jwks.keys.has(kid)){
   const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),Number(env.REALTIME_JWKS_TIMEOUT_MS||3000));
   try{
    const res=await fetch(issuer+"/protocol/openid-connect/certs",{signal:controller.signal});if(!res.ok)throw new Error("jwks_unavailable");
    const raw=Buffer.from(await res.arrayBuffer());if(raw.length>Number(env.REALTIME_JWKS_MAX_BYTES||262144))throw new Error("jwks_too_large");
    const body=JSON.parse(raw.toString("utf8"));jwks={expires:Date.now()+300000,keys:new Map((body.keys||[]).map(k=>[k.kid,k]))};
   } finally {clearTimeout(timeout);}
  }
  const jwk=jwks.keys.get(kid);if(!jwk)throw new Error("unknown_kid");return crypto.createPublicKey({key:jwk,format:"jwk"});
 }
 return async token=>{
  if(mode==="disabled")return {sub:"local-development",roles:["Administrator"],tenant_id:"local",application_id:"local-development"};
  if(!token)throw new Error("missing_bearer_token");
  if(token.length>Number(env.REALTIME_MAX_TOKEN_BYTES||16384))throw new Error("token_too_large");
  const parts=token.split(".");if(parts.length!==3)throw new Error("invalid_token");
  const header=jsonPart(parts[0]),claims=jsonPart(parts[1]);if(header.alg!=="RS256")throw new Error("invalid_alg");
  const key=await keyFor(header.kid);const ok=crypto.verify("RSA-SHA256",Buffer.from(parts[0]+"."+parts[1]),key,b64(parts[2]));if(!ok)throw new Error("invalid_signature");
  const now=Math.floor(Date.now()/1000),skew=Number(env.REALTIME_CLOCK_SKEW_SECONDS||30);
  if(claims.iss!==issuer||!claims.exp||claims.exp<=now-skew||!claims.iat||claims.iat>now+skew||claims.nbf>now+skew)throw new Error("invalid_claims");
  const aud=Array.isArray(claims.aud)?claims.aud:[claims.aud];if(!aud.includes(audience))throw new Error("invalid_audience");
  if(allowedAzp.size&&!allowedAzp.has(claims.azp))throw new Error("invalid_azp");
  const tenant=claims[tenantClaim];if(typeof tenant!=="string"||!tenant)throw new Error("tenant_claim_required");
  const rr=claims.realm_access?.roles||[],cr=claims.resource_access?.["mission-control"]?.roles||[];
  return {sub:claims.sub,roles:[...new Set([...rr,...cr])],tenant_id:tenant,application_id:claims.azp||null,claims};
 };
}

function validPayload(event){
 if(event.namespace==="agent"&&event.event_type==="heartbeat"){const p=event.payload;return !!p&&typeof p.agent_id==="string"&&typeof p.task_id==="string"&&SHA.test(p.current_sha||"")&&states.has(p.status)&&Number.isInteger(p.changed_files_count)&&p.changed_files_count>=0;}
 if(event.namespace==="mission"&&event.event_type==="state_transition"){const p=event.payload;return !!p&&typeof p.task_id==="string"&&states.has(p.previous_state)&&states.has(p.new_state)&&SHA.test(p.target_sha||"")&&typeof p.triggered_by==="string";}
 if(event.namespace==="mission"&&event.event_type==="task.claimed"){const p=event.payload;return !!p&&typeof p.task_id==="string"&&typeof p.agent_id==="string"&&typeof p.repository==="string";}
 if(event.namespace==="certification"&&event.event_type==="evidence_submitted"){const p=event.payload;return !!p&&UUID.test(p.certification_id||"")&&typeof p.task_id==="string"&&SHA.test(p.exact_sha||"")&&typeof p.test_pass_rate==="number"&&p.test_pass_rate>=0&&p.test_pass_rate<=100&&typeof p.artifact_url==="string";}
 return ["ci.status","repo.state_changed","notification.created","pr.updated","review.updated","testing.result"].includes(event.namespace+"."+event.event_type)&&Object.keys(event.payload||{}).length>0;
}
export function validEvent(event){return !!event&&typeof event==="object"&&UUID.test(event.event_id||"")&&Number.isInteger(event.sequence_no)&&event.sequence_no>=1&&allowedNamespaces.has(event.namespace)&&typeof event.event_type==="string"&&event.event_type.length>0&&typeof event.timestamp==="string"&&!Number.isNaN(Date.parse(event.timestamp))&&typeof event.source_service==="string"&&event.source_service.length>0&&event.payload&&typeof event.payload==="object"&&!Array.isArray(event.payload)&&(!event.correlation_id||UUID.test(event.correlation_id))&&(!event.causation_id||UUID.test(event.causation_id))&&validPayload(event);}
export function writePermission(event){const key=event.namespace+"."+event.event_type;if(key==="agent.heartbeat")return "agent:heartbeat";if(key.startsWith("mission."))return "mission:write";if(key==="certification.evidence_submitted")return "evidence:submit";if(["ci.status","repo.state_changed","pr.updated","review.updated","testing.result"].includes(key))return "evidence:submit";if(key==="notification.created")return "mission:write";return null;}
export function readPermission(event){if(event.namespace==="agent")return "agent:read";if(event.namespace==="certification")return "evidence:read";if(["ci","repo","pr","review","testing"].includes(event.namespace))return "evidence:read";return "mission:read";}
function authorizedLegacyEvent(user,event,mode){const permission=writePermission(event);if(!permission||!allows(user,permission))return false;if(mode==="required"&&event.tenant_id!==user.tenant_id)return false;return true;}

class Bucket{constructor(limit=120,windowMs=60000){this.limit=limit;this.windowMs=windowMs;this.map=new Map()}take(key){const now=Date.now();let x=this.map.get(key);if(!x||now-x.start>=this.windowMs)x={start:now,n:0};x.n++;this.map.set(key,x);return x.n<=this.limit}}
const readBody=(req,maxBytes)=>new Promise((resolve,reject)=>{let body="",size=0;req.on("data",c=>{size+=c.length;if(size>maxBytes){reject(Object.assign(new Error("payload_too_large"),{status:413}));req.destroy();return;}body+=c;});req.on("end",()=>{try{resolve(body?JSON.parse(body):{});}catch{reject(Object.assign(new Error("invalid_json"),{status:400}));}});req.on("error",reject);});
const validChannelName=name=>typeof name==="string"&&name.length>=1&&name.length<=255&&/^[a-zA-Z0-9._\-/:]+$/.test(name);
const canonicalEvent=(input,user,nextSequence)=>{
 if(!input||!validChannelName(input.channel)||typeof input.type!=="string"||!input.type||input.type.length>128||input.data===undefined)return null;
 return {id:crypto.randomUUID(),sequence:nextSequence(input.channel),channel:input.channel,type:input.type,timestamp:new Date().toISOString(),source:user.application_id||user.sub,tenant_id:user.tenant_id,correlation_id:UUID.test(input.correlation_id||"")?input.correlation_id:undefined,causation_id:UUID.test(input.causation_id||"")?input.causation_id:undefined,trace_id:typeof input.trace_id==="string"?input.trace_id:undefined,data:input.data};
};

export function createGateway({env=process.env}={}){
 let activeSha=env.REALTIME_BUILD_SHA||env.MISSION_CONTROL_BUILD_SHA||"";if(!activeSha){try{activeSha=execFileSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).trim()}catch{activeSha="0".repeat(40)}}
 const verifyJwt=createJwtVerifier(env),httpRate=new Bucket(Number(env.REALTIME_HTTP_RATE_LIMIT||env.MISSION_CONTROL_EVENT_RATE_LIMIT||120)),wsRate=new Bucket(Number(env.REALTIME_WS_RATE_LIMIT||env.MISSION_CONTROL_WS_RATE_LIMIT||240));
 const legacySequence=new Map(),channelSequence=new Map(),channels=new Map(),eventsById=new Map(),eventsByChannel=new Map();
 const nextSequence=channel=>{const n=(channelSequence.get(channel)||0)+1;channelSequence.set(channel,n);return n;};
 const acceptLegacySequence=event=>{const key=(event.tenant_id||"local")+":"+event.source_service+":"+event.namespace,last=legacySequence.get(key)||0;if(event.sequence_no<=last)return false;legacySequence.set(key,event.sequence_no);return true;};
 const recordEvent=event=>{eventsById.set(event.id,event);const list=eventsByChannel.get(event.channel)||[];list.push(event);const max=Number(env.REALTIME_MEMORY_RETENTION_EVENTS||1000);if(list.length>max)list.splice(0,list.length-max);eventsByChannel.set(event.channel,list);};
 const authorizeChannel=(user,channel,permission)=>{if(!allows(user,permission))return false;if(channel.startsWith("public/"))return true;return channel.startsWith("tenant/"+user.tenant_id+"/")||authMode(env)==="disabled";};
 const broadcastCanonical=event=>{const encoded=JSON.stringify({op:"event",event});for(const client of wss.clients){if(client.readyState!==1||!client.subscriptions?.has(event.channel))continue;if(!authorizeChannel(client.user,event.channel,"channel:subscribe"))continue;if(client.bufferedAmount>Number(env.REALTIME_WS_BACKPRESSURE_BYTES||1048576)){client.close(1013,"backpressure");continue;}client.send(encoded);}};
 const broadcastLegacy=event=>{const encoded=JSON.stringify(event);for(const client of wss.clients){if(client.readyState!==1)continue;if(authMode(env)==="required"&&client.user?.tenant_id!==event.tenant_id)continue;if(!allows(client.user,readPermission(event)))continue;if(client.bufferedAmount>1048576){client.close(1013,"backpressure");continue;}client.send(encoded);}};

 const server=http.createServer(async(req,res)=>{
  const requestId=String(req.headers["x-request-id"]||crypto.randomUUID());const url=new URL(req.url||"/","http://localhost");const path=url.pathname;
  if(path==="/health/live"||path==="/healthz")return sendJson(res,200,{ok:true,service:"codestra-realtime",version:"2.0.0",build_sha:activeSha,auth_mode:authMode(env)},requestId);
  if(path==="/health/ready")return sendJson(res,200,{ok:true,ready:true,dependencies:{broker:"memory",database:"memory"}},requestId);
  if(path==="/v1/system/info")return sendJson(res,200,{service:"codestra-realtime",version:"2.0.0",build_sha:activeSha,protocol:REALTIME_PROTOCOL},requestId);
  if(path==="/v1/system/version")return sendJson(res,200,{version:"2.0.0",build_sha:activeSha},requestId);
  if(path==="/v1/system/capabilities")return sendJson(res,200,{service:"codestra-realtime",version:"2.0.0",build_sha:activeSha,capabilities:{websocket:true,events:true,channels:true,presence:false,replay:false,rooms:false,webrtc:false,recording:false,broker:"memory",persistence:"memory"}},requestId);

  let user;try{user=await verifyJwt(extractToken(req));}catch{return sendError(res,401,"unauthorized","Authentication failed.",requestId);}
  const ip=req.socket.remoteAddress||"unknown";if(!httpRate.take(ip))return sendError(res,429,"rate_limited","Too many requests.",requestId);

  if(path==="/v1/channels"&&req.method==="GET"){if(!allows(user,"channel:read"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);return sendJson(res,200,{items:[...channels.values()].filter(c=>authorizeChannel(user,c.name,"channel:read"))},requestId);}
  if(path==="/v1/channels"&&req.method==="POST"){
   if(!allows(user,"channel:create"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);
   let body;try{body=await readBody(req,Number(env.REALTIME_HTTP_BODY_MAX||1048576));}catch(e){return sendError(res,e.status||400,e.message,e.message==="invalid_json"?"Invalid JSON.":"Request body is too large.",requestId);}
   if(!validChannelName(body.name)||!authorizeChannel(user,body.name,"channel:create"))return sendError(res,422,"invalid_channel","Channel name is invalid or outside the authenticated tenant.",requestId);
   if(channels.has(body.name))return sendError(res,409,"channel_exists","Channel already exists.",requestId);
   const channel={name:body.name,tenant_id:user.tenant_id,created_at:new Date().toISOString(),retention:body.retention||"memory"};channels.set(body.name,channel);return sendJson(res,201,channel,requestId);
  }
  const channelMatch=path.match(/^\/v1\/channels\/(.+)$/);
  if(channelMatch&&req.method==="GET"&&!path.endsWith("/events")){const name=decodeURIComponent(channelMatch[1]);const c=channels.get(name);if(!c)return sendError(res,404,"not_found","Channel not found.",requestId);if(!authorizeChannel(user,name,"channel:read"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);return sendJson(res,200,c,requestId);}
  if(channelMatch&&req.method==="DELETE"&&!path.endsWith("/events")){const name=decodeURIComponent(channelMatch[1]);if(!authorizeChannel(user,name,"channel:create"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);if(!channels.delete(name))return sendError(res,404,"not_found","Channel not found.",requestId);res.writeHead(204,{"x-request-id":requestId});return res.end();}
  const historyMatch=path.match(/^\/v1\/channels\/(.+)\/events$/);
  if(historyMatch&&req.method==="GET"){const name=decodeURIComponent(historyMatch[1]);if(!authorizeChannel(user,name,"event:read"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);const limit=Math.min(Math.max(Number(url.searchParams.get("limit")||100),1),500);const after=Number(url.searchParams.get("after")||0);const items=(eventsByChannel.get(name)||[]).filter(e=>e.sequence>after).slice(0,limit);return sendJson(res,200,{items,next_cursor:items.length?String(items.at(-1).sequence):null},requestId);}

  if(path==="/v1/events"&&req.method==="POST"){
   if(!allows(user,"event:publish"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);
   let body;try{body=await readBody(req,Number(env.REALTIME_HTTP_BODY_MAX||1048576));}catch(e){return sendError(res,e.status||400,e.message,e.message==="invalid_json"?"Invalid JSON.":"Request body is too large.",requestId);}
   if(!authorizeChannel(user,body.channel,"channel:publish"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);
   const event=canonicalEvent(body,user,nextSequence);if(!event)return sendError(res,422,"invalid_event","Event payload is invalid.",requestId);
   recordEvent(event);broadcastCanonical(event);return sendJson(res,202,event,requestId);
  }
  const eventMatch=path.match(/^\/v1\/events\/([0-9a-f-]+)$/i);
  if(eventMatch&&req.method==="GET"){const event=eventsById.get(eventMatch[1]);if(!event)return sendError(res,404,"not_found","Event not found.",requestId);if(!authorizeChannel(user,event.channel,"event:read"))return sendError(res,403,"forbidden","Request is not permitted.",requestId);return sendJson(res,200,event,requestId);}

  if(path==="/events"&&req.method==="POST"){
   let body;try{body=await readBody(req,1048576);}catch(e){return sendError(res,e.status||400,e.message,"Invalid request.",requestId);}
   if(!validEvent(body))return sendError(res,422,"invalid_event","Legacy event payload is invalid.",requestId);
   if(!authorizedLegacyEvent(user,body,authMode(env)))return sendError(res,403,"forbidden","Request is not permitted.",requestId);
   if(!acceptLegacySequence(body))return sendError(res,409,"replay","Sequence was already accepted.",requestId);
   broadcastLegacy(body);res.writeHead(202,{"x-request-id":requestId});return res.end();
  }
  return sendError(res,404,"not_found","Route not found.",requestId);
 });

 const wss=new WebSocketServer({server,maxPayload:Number(env.REALTIME_WS_FRAME_MAX||1048576),verifyClient:(info,cb)=>{
   const origin=info.req.headers.origin,allowed=(env.REALTIME_ALLOWED_ORIGINS||"").split(",").map(x=>x.trim()).filter(Boolean);
   if(origin&&allowed.length&&!allowed.includes(origin))return cb(false,403,"Forbidden");
   verifyJwt(extractToken(info.req)).then(u=>{info.req.user=u;cb(true)}).catch(()=>cb(false,401,"Unauthorized"));
 },handleProtocols:protocols=>protocols.has(REALTIME_PROTOCOL)?REALTIME_PROTOCOL:(protocols.has("mission-control")?"mission-control":false)});

 wss.on("connection",(socket,req)=>{
  socket.isAlive=true;socket.user=req.user;socket.subscriptions=new Set();socket.on("pong",()=>socket.isAlive=true);
  socket.send(JSON.stringify({op:"connected",connection_id:crypto.randomUUID(),protocol:socket.protocol||REALTIME_PROTOCOL}));
  socket.on("message",raw=>{
   if(!wsRate.take(socket.user?.sub||req.socket.remoteAddress||"unknown"))return socket.close(1013,"rate_limited");
   let msg;try{msg=JSON.parse(raw.toString());}catch{return socket.close(1007,"invalid_json");}
   if(msg?.op==="ping")return socket.send(JSON.stringify({op:"pong",timestamp:new Date().toISOString()}));
   if(msg?.op==="subscribe"){if(!validChannelName(msg.channel)||!authorizeChannel(socket.user,msg.channel,"channel:subscribe"))return socket.send(JSON.stringify({op:"error",error:{code:"forbidden",message:"Subscription is not permitted."}}));socket.subscriptions.add(msg.channel);return socket.send(JSON.stringify({op:"subscribed",channel:msg.channel}));}
   if(msg?.op==="unsubscribe"){socket.subscriptions.delete(msg.channel);return socket.send(JSON.stringify({op:"unsubscribed",channel:msg.channel}));}
   if(msg?.op==="publish"){if(!authorizeChannel(socket.user,msg.channel,"channel:publish"))return socket.send(JSON.stringify({op:"error",error:{code:"forbidden",message:"Publish is not permitted."}}));const event=canonicalEvent({channel:msg.channel,type:msg.type,data:msg.data,correlation_id:msg.correlation_id,causation_id:msg.causation_id,trace_id:msg.trace_id},socket.user,nextSequence);if(!event)return socket.send(JSON.stringify({op:"error",error:{code:"invalid_event",message:"Event payload is invalid."}}));recordEvent(event);broadcastCanonical(event);return;}
   if(validEvent(msg)){if(!authorizedLegacyEvent(socket.user,msg,authMode(env)))return socket.close(1008,"forbidden");if(!acceptLegacySequence(msg))return socket.close(1008,"replay");broadcastLegacy(msg);return;}
   socket.close(1007,"invalid_frame");
  });
 });
 const timer=setInterval(()=>{for(const socket of wss.clients){if(!socket.isAlive){socket.terminate();continue;}socket.isAlive=false;socket.ping();}},Number(env.REALTIME_HEARTBEAT_MS||30000));timer.unref();
 return {server,wss,broadcast:broadcastCanonical,channels,eventsById,eventsByChannel};
}

export function assertSafeBind(env=process.env,host=env.HOST||"127.0.0.1"){
 if(authMode(env)==="disabled"&&!["127.0.0.1","::1","localhost"].includes(host))throw new Error("AUTH_MODE=disabled may only bind to loopback");
 return host;
}
if(process.argv[1]===new URL(import.meta.url).pathname){
 const env=process.env,host=assertSafeBind(env),{server}=createGateway({env});
 server.listen(Number(env.PORT||8787),host,()=>console.log(`codestra-realtime ready on ${host}:${env.PORT||8787}`));
}
