// Shared JSON-lines harness for offline synthetic Rust oracle examples.
const {spawn,spawnSync}=require('node:child_process'),readline=require('node:readline'),assert=require('node:assert/strict');
function buildDriver(root,example){
 const result=spawnSync('cargo',['build','--locked','--quiet','--message-format=json','--example',example],{cwd:root,env:{...process.env,CARGO_BUILD_JOBS:'1'},encoding:'utf8',maxBuffer:4*1024*1024});
 if(result.status!==0)throw Error(result.stderr||'Rust oracle build failed');
 const artifact=result.stdout.trim().split('\n').filter(Boolean).map(line=>JSON.parse(line)).find(message=>message.reason==='compiler-artifact'&&message.target.name===example&&message.executable);
 assert(artifact,'Cargo did not return the oracle executable');return artifact.executable;
}
function startDriver(executable,args,root){
 const child=spawn(executable,args,{cwd:root,stdio:['pipe','pipe','pipe']});let pending,terminal,ended=false,stderr='';
 const fail=error=>{terminal=error;if(pending){clearTimeout(pending.timer);pending.reject(error);pending=undefined;}};
 child.stderr.on('data',data=>{stderr=(stderr+data.toString()).slice(-8192);});
 const lines=readline.createInterface({input:child.stdout});
 lines.on('line',line=>{if(!pending){fail(Error('Unexpected oracle response'));child.kill();return;}const {resolve,reject,timer}=pending;pending=undefined;clearTimeout(timer);try{const result=JSON.parse(line);result.ok?resolve(result.value):reject(Error(result.error));}catch(error){reject(error);}});
 child.on('error',fail);child.stdin.on('error',fail);child.on('close',(code,signal)=>{ended=true;fail(Error(`Rust oracle closed (${code??signal}): ${stderr}`));});
 const request=data=>{assert(!pending,'Oracle requests must be serial');if(terminal)return Promise.reject(terminal);const line=JSON.stringify(data)+'\n';return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{fail(Error(`Rust oracle timed out during ${data.command}`));child.kill();},30000);pending={resolve,reject,timer};child.stdin.write(line);});};
 const stop=kill=>new Promise(resolve=>{if(ended)return resolve();child.once('close',resolve);if(kill)child.kill();else child.stdin.end();});
 return {request,close:()=>stop(false),kill:()=>stop(true)};
}
module.exports={buildDriver,startDriver};
