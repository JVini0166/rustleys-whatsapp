// Execute the pinned original rotation closure, not a rewritten JS equivalent.
const ts=require('typescript'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {setup}=require('./prekeys-reference.cjs'),{storage,bundle,signal,tagged}=require('./signal-reference.cjs'),{buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{
 const r=await setup(process.argv[2]),root=path.join(__dirname,'..'),tree=ts.createSourceFile('socket.ts',r.source('src/Socket/socket.ts'),ts.ScriptTarget.Latest,true);let declaration;
 function find(n){if(ts.isVariableDeclaration(n)&&n.name.getText(tree)==='rotateSignedPreKey')declaration=n.getText(tree);ts.forEachChild(n,find);}find(tree);assert(declaration);
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'rustleys-signed-')),file=path.join(temp,'keys.sqlite'),exe=buildDriver(root,'signed_keys_crosscheck');let driver=startDriver(exe,[file],root),comparisons=0,messages=0;
 const original=r.credentials[0],serialize=c=>JSON.parse(JSON.stringify(c,r.BufferJSON.replacer));
 try{
  const request=(command,extra={})=>driver.request({command,credentials:serialize(original),...extra});
  let expected=original.signedPreKey.keyId+1,active=original;
  async function rotate(success){
   const prepared=await request('rotate');assert.equal(prepared.id,expected++);
   const key=JSON.parse(JSON.stringify(prepared.key),r.BufferJSON.reviver);
   // Validate the boolean from libsignal's raw verifier; the Baileys wrapper
   // discards false and isInit in SessionBuilder can skip verification.
   const curve=require('libsignal/src/curve');
   assert.equal(curve.verifySignature(tagged(original.signedIdentityKey.public),tagged(key.keyPair.public),key.signature),true);
   const invalid=Buffer.from(key.signature);invalid[0]^=1;
   assert.equal(curve.verifySignature(tagged(original.signedIdentityKey.public),tagged(key.keyPair.public),invalid),false);
   let sent,updates=[];
   const inputs={creds:active,signedKeyPair:async(identity,id)=>{assert.equal(id,prepared.id);assert.equal(identity,active.signedIdentityKey);return key;},query:async node=>{sent=node;if(!success)throw Error('synthetic lost ack');},xmppSignedPreKey:r.xmppSignedPreKey,S_WHATSAPP_NET:'@s.whatsapp.net',ev:{emit:(name,update)=>{assert.equal(name,'creds.update');updates.push(update);}}};
   const rotate=r.compile('const {creds,signedKeyPair,query,xmppSignedPreKey,S_WHATSAPP_NET,ev}=require("inputs");\nexport const '+declaration,n=>n==='inputs'?inputs:require(n)).rotateSignedPreKey;
   if(success)await rotate();else await assert.rejects(rotate(),/lost ack/);
   assert.deepEqual(Buffer.from(prepared.wire),r.binary.encodeBinaryNode(sent));comparisons++;
   assert.equal(updates.length,success?1:0);
   if(success){await request('confirm',{id:prepared.id});active={...active,signedPreKey:updates[0].signedPreKey};}
   assert.equal((await request('active')).keyId,active.signedPreKey.keyId);
   return {...original,signedPreKey:key};
  }
  const retired=original,current=await rotate(true),uncertain=await rotate(false);
  // Restart the Rust process with stale credentials, retaining native history.
  await driver.close();driver=startDriver(exe,[file],root);
  assert.equal((await request('active')).keyId,current.signedPreKey.keyId);
  for(const [i,target]of [retired,current,uncertain].entries()){
   const peer=storage(r.credentials[1]),address=new signal.ProtocolAddress('synthetic-target',2);
   await new signal.SessionBuilder(peer,address).initOutgoing(bundle(target));
   const plain=Buffer.from(`signed-key-history-${i}`),cipher=await new signal.SessionCipher(peer,address).encrypt(plain);
   // Different sender addresses are needed for independent sessions.
   const result=await driver.request({command:'decrypt',credentials:serialize(original),sender:`synthetic-peer-${i}:1@s.whatsapp.net`,ciphertext:Array.from(Buffer.from(cipher.body))});
   assert.deepEqual(Buffer.from(result),plain);messages++;
  }
  console.log(`${comparisons} original signed-key rotation wire/ack comparisons and ${messages} fresh Node→Rust handshakes using retired, active and unconfirmed keys after process restart passed`);
 }finally{await driver.kill();await fs.rm(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
