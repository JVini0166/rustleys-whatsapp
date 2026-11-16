const fs=require('node:fs'),path=require('node:path');
const {setup,storage,signal}=require('./signal-reference.cjs');
const assert=require('node:assert/strict');
const {context,decrypt,peerAddress}=require('./legacy-session-reference.cjs');
console.info=()=>{};console.warn=()=>{};
(async()=>{
 const r=await setup(process.argv[2]),cases=[];
 for(const mode of ['pending','established','archived','archived-prekey'])for(const oneTime of [false,true])for(const targetStarts of (mode==='pending'?[true]:mode==='archived-prekey'?[false]:[false,true])){
  const c=await context(r,mode,oneTime,targetStarts);
  const snapshot=(await c.target.loadSession(peerAddress.toString())).serialize(),check=storage(r.credentials[0]);check.sessions.set(peerAddress.toString(),snapshot);const cipher=new signal.SessionCipher(check,peerAddress);for(const packet of c.incoming)assert.deepEqual(await decrypt(cipher,packet),Buffer.from(packet.plaintext));
  cases.push({mode,one_time:oneTime,target_starts:targetStarts,credentials:r.credentialJson[0],jid:c.jid,record:(await c.target.loadSession(peerAddress.toString())).serialize(),incoming:c.incoming});
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/legacy-sessions-upstream.json'),JSON.stringify({upstream_commit:r.commit,libsignal_version:require('libsignal/package.json').version,synthetic_data:true,cases},null,2)+'\n');
 const broken=await context(r,'archived',false,false,{tiedClock:true}),snapshot=(await broken.target.loadSession(peerAddress.toString())).serialize(),check=storage(r.credentials[0]);check.sessions.set(peerAddress.toString(),snapshot);const cipher=new signal.SessionCipher(check,peerAddress);for(const packet of broken.incoming.slice(0,3))await decrypt(cipher,packet);const oldError=console.error;console.error=()=>{};try{await assert.rejects(decrypt(cipher,broken.incoming[3]));}finally{console.error=oldError;}
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/legacy-archive-regression.json'),JSON.stringify({upstream_commit:r.commit,libsignal_version:'6.0.0',synthetic_data:true,credentials:r.credentialJson[0],jid:broken.jid,record:snapshot,incoming:broken.incoming,original_rejects_packet:3},null,2)+'\n');
 console.log(`${cases.length} original libsignal-node session JSON fixtures generated: pending prekeys, ratchets, skipped keys and archives`);
})().catch(e=>{console.error(e.message);process.exitCode=1;});
