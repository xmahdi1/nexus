import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
const source=readFileSync(new URL('../src/lib/socket.ts',import.meta.url),'utf8')
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {managedSocket}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
function fixture(authorize=async()=>true,maxRetries=2){
 const sockets=[],timers=[],statuses=[]
 const stream=managedSocket({authorize,url:()=>'/fixture',maxRetries,message:()=>{},status:s=>statuses.push(s),create:()=>{const socket={close(){this.closed=true},readyState:1,send(){}};sockets.push(socket);return socket},delay:(fn,ms)=>{const timer={fn,ms};timers.push(timer);return timer},cancel:timer=>{timer.cancelled=true}})
 return {stream,sockets,timers,statuses}
}
test('disposal while authentication pending never creates a socket',async()=>{
 let finish;const f=fixture(()=>new Promise(resolve=>finish=resolve));const pending=f.stream.connect();f.stream.dispose();finish(true);await pending;assert.equal(f.sockets.length,0)
})
test('revoked resource permission stops retry after auth recheck',async()=>{
 let valid=true;const f=fixture(async()=>valid);await f.stream.connect();valid=false;f.sockets[0].onclose({code:1006});assert.equal(f.timers[0].ms,1000);await f.timers[0].fn();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.sockets.length,1);assert.equal(f.statuses.at(-1),'denied')
})
test('retries are bounded, disposal clears timers and stale socket callbacks',async()=>{
 const f=fixture();await f.stream.connect();for(let i=0;i<2;i++){f.sockets.at(-1).onclose({code:1006});await f.timers.at(-1).fn();await new Promise(resolve=>setImmediate(resolve))}
 f.sockets.at(-1).onclose({code:1006});assert.equal(f.sockets.length,3);assert.equal(f.timers.length,2);assert.equal(f.statuses.at(-1),'closed')
 const g=fixture();await g.stream.connect();const old=g.sockets[0].onclose;g.stream.dispose();old({code:1006});assert.equal(g.timers.length,0)
})
test('policy close is terminal and superseded auth response cannot reopen socket',async()=>{
 const f=fixture();await f.stream.connect();f.sockets[0].onclose({code:1008});assert.equal(f.timers.length,0);assert.equal(f.statuses.at(-1),'denied')
 const resolvers=[];const g=fixture(()=>new Promise(resolve=>resolvers.push(resolve)));const a=g.stream.connect(),b=g.stream.connect();resolvers[1](true);await b;resolvers[0](true);await a;assert.equal(g.sockets.length,1)
})
