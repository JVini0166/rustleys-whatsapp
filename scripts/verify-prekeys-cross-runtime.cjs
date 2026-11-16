const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {setup,keyStore}=require('./prekeys-reference.cjs');const {storage,bundle,signal}=require('./signal-reference.cjs');const {buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{const root=path.join(__dirname,'..'),r=await setup(process.argv[2]),executable=buildDriver(root,'prekeys_crosscheck'),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'rustleys-prekeys-peer-'));let driver,comparisons=0,messages=0;
 try{
 for(const[first,next,count]of [[1,1,5],[10,20,5],[10,20,12],[0,0,1],[0xfffffd,0xfffffd,3],[1,1,812]]){
  console.log(`case first=${first} next=${next} count=${count}`);
  const creds={...r.credentials[0],nextPreKeyId:next,firstUnuploadedPreKeyId:first},keys={};for(let id=first;id<next;id++)keys[id]=r.crypto.Curve.generateKeyPair();
  driver=startDriver(executable,[path.join(temporary,`${first}-${next}-${count}.sqlite`)],root);const credentials=JSON.parse(JSON.stringify(creds,r.BufferJSON.replacer));const prepared=await driver.request({command:'prepare',credentials,count,keys:JSON.parse(JSON.stringify(keys,r.BufferJSON.replacer))});
  const produced=JSON.parse(JSON.stringify(prepared.keys),r.BufferJSON.reviver);let id=next;const oracle=await setup(process.argv[2],()=>{const key=produced[id++];assert(key,'Native-generated entropy missing');return key;});
  const original=await oracle.getNextPreKeysNode({creds,keys:keyStore(keys)},count);assert.deepEqual(prepared.update,original.update);assert.deepEqual(Buffer.from(prepared.wire),r.binary.encodeBinaryNode(original.node));comparisons++;
  // The actual Node peer encrypts with the exported public prekey. Rust must
  // decrypt with the private record atomically written by its reservation path.
  const peer=storage(r.credentials[1]),address=new signal.ProtocolAddress('synthetic-target',2);const selected=first+count-1;const prekey={id:selected,key:produced[selected]};await new signal.SessionBuilder(peer,address).initOutgoing(bundle(creds,prekey));const plain=Buffer.from([0,255,first&255,count&255]),encrypted=await new signal.SessionCipher(peer,address).encrypt(plain);assert.deepEqual(Buffer.from(await driver.request({command:'decrypt',credentials,ciphertext:Array.from(Buffer.from(encrypted.body))})),plain);assert.equal(await driver.request({command:'has',credentials,id:selected}),false);messages++;
  await driver.close();driver=undefined;
 }
 console.log(`${comparisons} original prekey upload wire/counter comparisons passed, including fresh generation, reuse, zero ID, maximum ID and the 812-key initial batch; ${messages} real Node→Rust prekey handshakes decrypted and consumed their private key`);
 }finally{if(driver)await driver.kill();await fs.rm(temporary,{recursive:true,force:true});}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
