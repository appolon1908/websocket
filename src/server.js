import http from "node:http";
import { WebSocketServer } from "ws";
const allowedPrefixes=["agent.","mission.","ci.","repo.","notification.","market.","crypto.","pr.","review.","testing.","certification."];
export function validEvent(event){return event&&typeof event.type==="string"&&allowedPrefixes.some(p=>event.type.startsWith(p))&&typeof event.ts==="string"&&event.payload&&typeof event.payload==="object";}
export function createGateway(){
 const server=http.createServer((req,res)=>{
  if(req.url==="/healthz"){res.writeHead(200,{"content-type":"application/json"});return res.end('{"ok":true}');}
  if(req.url==="/events"&&req.method==="POST"){let body="";req.on("data",c=>{body+=c;if(body.length>1048576)req.destroy();});req.on("end",()=>{let event;try{event=JSON.parse(body);}catch{res.writeHead(400);return res.end();}if(!validEvent(event)){res.writeHead(422);return res.end();}broadcast(event);res.writeHead(202);res.end();});return;}
  res.writeHead(404);res.end();
 });
 const wss=new WebSocketServer({server,maxPayload:1048576});
 const broadcast=(event)=>{const encoded=JSON.stringify(event);for(const client of wss.clients)if(client.readyState===1)client.send(encoded);};
 wss.on("connection",socket=>{socket.isAlive=true;socket.on("pong",()=>socket.isAlive=true);socket.on("message",raw=>{let event;try{event=JSON.parse(raw.toString());}catch{return socket.send(JSON.stringify({type:"error.invalid_json"}));}if(!validEvent(event))return socket.send(JSON.stringify({type:"error.invalid_event"}));broadcast(event);});});
 const timer=setInterval(()=>{for(const socket of wss.clients){if(!socket.isAlive){socket.terminate();continue;}socket.isAlive=false;socket.ping();}},30000);timer.unref();
 return {server,wss,broadcast};
}
if(process.argv[1]===new URL(import.meta.url).pathname){const {server}=createGateway();server.listen(Number(process.env.PORT||8787),"127.0.0.1",()=>console.log("realtime-gateway ready"));}
