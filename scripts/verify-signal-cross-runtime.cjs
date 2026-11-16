// Active offline peers: actual libsignal-node and the native Rust repository.
const fsp=require('node:fs').promises,path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict'),readline=require('node:readline'),{spawn,spawnSync}=require('node:child_process');
const {setup,storage,bundle,signal}=require('./signal-reference.cjs');
(async()=>{
 const root=path.join(__dirname,'..'),r=await setup(process.argv[2]);
 const build=spawnSync('cargo',['build','--locked','--quiet','--message-format=json','--example','signal_crosscheck'],{cwd:root,env:{...process.env,CARGO_BUILD_JOBS:'1'},encoding:'utf8',maxBuffer:2*1024*1024});if(build.status!==0)throw Error(build.stderr||'Rust build failed');
 const artifact=build.stdout.trim().split('\n').filter(Boolean).map(line=>JSON.parse(line)).find(message=>message.reason==='compiler-artifact'&&message.target.name==='signal_crosscheck'&&message.executable);assert(artifact,'Cargo did not return the example executable');
 const temp=await fsp.mkdtemp(path.join(os.tmpdir(),'rustleys-signal-interop-'));
 let calls=0,packets=0,current;
 async function start(db){
  const process=spawn(artifact.executable,[db],{cwd:root,stdio:['pipe','pipe','pipe']});
  let pending,stderr='';process.stderr.on('data',d=>{stderr+=d.toString();});const lines=readline.createInterface({input:process.stdout});
  lines.on('line',line=>{if(!pending)return;const {resolve,reject,timer}=pending;pending=undefined;clearTimeout(timer);try{const result=JSON.parse(line);result.ok?resolve(result.value):reject(Error(result.error));}catch(e){reject(e);}});
  process.on('error',error=>{if(pending){clearTimeout(pending.timer);pending.reject(error);pending=undefined;}});
  process.on('exit',()=>{if(pending){clearTimeout(pending.timer);pending.reject(Error(`Rust exited: ${stderr}`));pending=undefined;}});
  const request=data=>{assert(!pending,'serial request protocol');calls++;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending=undefined;reject(Error('Rust request timed out'));process.kill();},30000);pending={resolve,reject,timer};process.stdin.write(JSON.stringify(data)+'\n');});};
  return {request,close:()=>new Promise(resolve=>{if(process.exitCode!==null||process.signalCode!==null)return resolve();process.once('exit',resolve);process.stdin.end();}),kill:()=>new Promise(resolve=>{if(process.exitCode!==null||process.signalCode!==null)return resolve();process.once('exit',resolve);process.kill();})};
 }
 const wireBundle=b=>({...b,identityKey:Array.from(b.identityKey),signedPreKey:{...b.signedPreKey,publicKey:Array.from(b.signedPreKey.publicKey),signature:Array.from(b.signedPreKey.signature)},...(b.preKey?{preKey:{...b.preKey,publicKey:Array.from(b.preKey.publicKey)}}:{})});
 try{
  for(const initiator of ['node','rust'])for(const oneTime of [false,true]){
   const db=path.join(temp,`${initiator}-${oneTime}.sqlite`),alice=r.credentials[0],bob=r.credentials[1],node=storage(alice),pre=r.crypto.Curve.generateKeyPair(),jid='synthetic-alice:1@s.whatsapp.net';
   current=await start(db);let request=data=>current.request(data);await request({command:'configure',credentials:JSON.parse(r.credentialJson[1])});
   const nodeAddress=new signal.ProtocolAddress('synthetic-bob',2),cipher=new signal.SessionCipher(node,nodeAddress);
   if(initiator==='node'){
    if(oneTime)await request({command:'put_prekey',id:7,key:JSON.parse(JSON.stringify(pre,r.BufferJSON.replacer))});
    await new signal.SessionBuilder(node,nodeAddress).initOutgoing(bundle(bob,oneTime?{id:7,key:pre}:null));
   }else{
    if(oneTime)node.prekeys.set(7,pre);await request({command:'inject',jid,bundle:wireBundle(bundle(alice,oneTime?{id:7,key:pre}:null))});
   }
   const nodeToRust=async plaintext=>{const encrypted=await cipher.encrypt(plaintext);const kind=encrypted.type===3?'pkmsg':'msg';const wire=Array.from(Buffer.from(encrypted.body));assert.deepEqual(Buffer.from(await request({command:'decrypt',jid,type:kind,ciphertext:wire})),plaintext);packets++;return {type:kind,ciphertext:wire};};
   const rustToNode=async plaintext=>{const encrypted=await request({command:'encrypt',jid,plaintext:Array.from(plaintext)});const method=encrypted.type==='pkmsg'?'decryptPreKeyWhisperMessage':'decryptWhisperMessage';assert.deepEqual(await cipher[method](Buffer.from(encrypted.ciphertext)),plaintext);packets++;return encrypted;};
   if(initiator==='node')await nodeToRust(Buffer.from('node starts'));else await rustToNode(Buffer.from('rust starts'));
   for(let round=0;round<5;round++){await rustToNode(Buffer.from([0,255,round]));await nodeToRust(Buffer.from(`node reply ${round}`));}
   // Receive in a different order from send order on both sides.
   const nodePackets=[];for(let n=0;n<4;n++){const encrypted=await cipher.encrypt(Buffer.from(`queued-node-${n}`));nodePackets.push({type:encrypted.type===3?'pkmsg':'msg',ciphertext:Array.from(Buffer.from(encrypted.body))});}
   for(const n of [3,0,2,1]){assert.deepEqual(Buffer.from(await request({command:'decrypt',jid,...nodePackets[n]})),Buffer.from(`queued-node-${n}`));packets++;}
   const rustPackets=[];for(let n=0;n<4;n++)rustPackets.push(await request({command:'encrypt',jid,plaintext:Array.from(Buffer.from(`queued-rust-${n}`))}));
   for(const n of [2,0,3,1]){assert.deepEqual(await cipher.decryptWhisperMessage(Buffer.from(rustPackets[n].ciphertext)),Buffer.from(`queued-rust-${n}`));packets++;}
   await assert.rejects(request({command:'decrypt',jid,...nodePackets[0]}));
   const info=await request({command:'info',jid});const nodeSession=(await node.loadSession(nodeAddress.toString())).getOpenSession();assert.deepEqual(Buffer.from(info.baseKey),nodeSession.indexInfo.baseKey);assert.equal(info.registrationId,alice.registrationId);
   // Stop/reopen the actual Rust process and SQLite connection, preserving the JS peer.
   await current.close();current=await start(db);await request({command:'configure',credentials:JSON.parse(r.credentialJson[1])});await nodeToRust(Buffer.alloc(4096,173));await rustToNode(Buffer.alloc(17,87));
   if(oneTime){if(initiator==='node')assert.equal(await request({command:'has_prekey',id:7}),false);else assert.equal(node.prekeys.has(7),false);}
   await current.close();current=undefined;
  }
  console.log(`${packets} bidirectional messages accepted by independent Node/Rust peers across 4 sessions; ratchets, reordering, duplicates and process restarts verified (${calls} Rust operations)`);
 }finally{if(current)await current.kill();await fsp.rm(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
