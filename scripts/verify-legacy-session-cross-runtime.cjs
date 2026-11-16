// A Node session is stopped, imported to Rust, and resumed against its live peer.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {setup,storage,signal}=require('./signal-reference.cjs');
const {context,packet,decrypt,peerAddress}=require('./legacy-session-reference.cjs');
const {buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
console.info=()=>{};console.warn=()=>{};
(async()=>{
 const r=await setup(process.argv[2]),root=path.join(__dirname,'..'),executable=buildDriver(root,'signal_crosscheck'),temp=await fs.mkdtemp(path.join(os.tmpdir(),'rustleys-legacy-import-'));
 let current,calls=0,messages=0,contexts=0,phase="";
 try{
 for(let repetition=0;repetition<5;repetition++)for(const mode of ['pending','established','archived','archived-prekey'])for(const oneTime of [false,true])for(const targetStarts of (mode==='pending'?[true]:mode==='archived-prekey'?[false]:[false,true])){
  console.log(`checking ${mode} prekey=${oneTime} targetStarts=${targetStarts}`);
  const c=await context(r,mode,oneTime,targetStarts),db=path.join(temp,`${repetition}-${mode}-${oneTime}-${targetStarts}.sqlite`);
  current=startDriver(executable,[db],root);const request=async data=>{calls++;try{return await current.request(data);}catch(error){throw Error(`${mode}/${oneTime}/${targetStarts} phase=${phase} command=${data.command}: ${error.message}`);}};
  await request({command:'configure',credentials:JSON.parse(r.credentialJson[0])});
  const record=(await c.target.loadSession(peerAddress.toString())).serialize();
  const check=storage(r.credentials[0]);check.sessions.set(peerAddress.toString(),JSON.parse(JSON.stringify(record)));const originalCipher=new signal.SessionCipher(check,peerAddress);for(const packet of c.incoming)assert.deepEqual(await decrypt(originalCipher,packet),Buffer.from(packet.plaintext));
  const report=await request({command:'legacy_import',jid:c.jid,record});
  assert.equal(report.open_sessions,1);assert.equal(report.archived_sessions,mode.startsWith('archived')?1:0);
  for(const p of c.incoming){phase=`incoming-${c.incoming.indexOf(p)}`;assert.deepEqual(Buffer.from(await request({command:'decrypt',jid:c.jid,type:p.type,ciphertext:p.ciphertext})),Buffer.from(p.plaintext));messages++;}
  await assert.rejects(request({command:'legacy_import',jid:c.jid,record}));
  const toNode=async text=>{phase=`toNode-${text.toString("hex")}`;const p=await request({command:'encrypt',jid:c.jid,plaintext:Array.from(text)});try{assert.deepEqual(await decrypt(c.peerCipher,p),text);}catch(error){throw Error(`${mode}/${oneTime}/${targetStarts} Node decrypt: ${error.message}`);}messages++;};
  const toRust=async text=>{phase=`toRust-${text.toString("hex")}`;const p=await packet(c.peerCipher,text);assert.deepEqual(Buffer.from(await request({command:'decrypt',jid:c.jid,type:p.type,ciphertext:p.ciphertext})),text);messages++;};
  for(let round=0;round<4;round++){await toNode(Buffer.from([0,round,255]));await toRust(Buffer.from(`continued ${round}`));}
  await current.close();current=startDriver(executable,[db],root);await request({command:'configure',credentials:JSON.parse(r.credentialJson[0])});
  await toRust(Buffer.alloc(73,193));await toNode(Buffer.alloc(16,0));
  await current.close();current=undefined;contexts++;
 }
 console.log(`${messages} messages verified after importing original JSON sessions across ${contexts} contexts; pending prekeys, both initiators, skipped keys, archives, overwrite rejection and native process restart passed (${calls} Rust operations)`);
 }finally{if(current)await current.kill();await fs.rm(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
