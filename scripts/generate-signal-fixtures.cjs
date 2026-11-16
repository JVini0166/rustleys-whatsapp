const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {setup,storage,bundle,signal}=require('./signal-reference.cjs');
(async()=>{
 const r=await setup(process.argv[2]),cases=[];
 for(const oneTime of [false,true]){
  const alice=r.credentials[0],bob=r.credentials[1],a=storage(alice),b=storage(bob),key=r.crypto.Curve.generateKeyPair();if(oneTime)b.prekeys.set(7,key);
  const address=new signal.ProtocolAddress('synthetic-bob',1);await new signal.SessionBuilder(a,address).initOutgoing(bundle(bob,oneTime?{id:7,key}:null));
  const cipher=new signal.SessionCipher(a,address),receiver=new signal.SessionCipher(b,new signal.ProtocolAddress('synthetic-alice',1)),packets=[];
  for(const n of [0,1,15,16,17,64,255,4096]){
   const plaintext=Buffer.from(Array.from({length:n},(_,i)=>(n+i*31)&255)),encrypted=await cipher.encrypt(plaintext);assert.equal(encrypted.type,3);
   assert.deepEqual(await receiver.decryptPreKeyWhisperMessage(Buffer.from(encrypted.body)),plaintext);
   packets.push({plaintext:Array.from(plaintext),type:'pkmsg',ciphertext:Array.from(Buffer.from(encrypted.body))});
  }
  cases.push({one_time:oneTime,alice_credentials:r.credentialJson[0],bob_credentials:r.credentialJson[1],prekey:oneTime?JSON.stringify(key,r.BufferJSON.replacer):null,packets});
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/signal-upstream.json'),JSON.stringify({upstream_commit:r.commit,libsignal_version:require('libsignal/package.json').version,synthetic_data:true,cases})+'\n');
 console.log('16 original libsignal-node prekey messages, with and without a one-time prekey');
})().catch(e=>{console.error(e.message);process.exitCode=1;});
