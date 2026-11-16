// Development-only sessions produced by the actual libsignal-node dependency.
const {storage,bundle,signal}=require('./signal-reference.cjs');
const peerAddress=new signal.ProtocolAddress('legacy-peer',2);
const targetAddress=new signal.ProtocolAddress('legacy-target',1);
const jid='legacy-peer:2@s.whatsapp.net';
const packet=async(cipher,plaintext)=>{const encrypted=await cipher.encrypt(plaintext);return {type:encrypted.type===3?'pkmsg':'msg',ciphertext:Array.from(Buffer.from(encrypted.body)),plaintext:Array.from(plaintext)};};
const decrypt=async(cipher,p)=>cipher[p.type==='pkmsg'?'decryptPreKeyWhisperMessage':'decryptWhisperMessage'](Buffer.from(p.ciphertext));
async function buildContext(r,mode,oneTime,targetStarts=true){
 const targetCreds=r.credentials[0],peerCreds=r.credentials[1],target=storage(targetCreds),peer=storage(peerCreds);
 const targetCipher=new signal.SessionCipher(target,peerAddress),peerCipher=new signal.SessionCipher(peer,targetAddress);
 let preId=7;
 const establish=async()=>{
  const pre=r.crypto.Curve.generateKeyPair();
  if(targetStarts){if(oneTime)peer.prekeys.set(preId,pre);await new signal.SessionBuilder(target,peerAddress).initOutgoing(bundle(peerCreds,oneTime?{id:preId,key:pre}:null));}
  else {if(oneTime)target.prekeys.set(preId,pre);await new signal.SessionBuilder(peer,targetAddress).initOutgoing(bundle(targetCreds,oneTime?{id:preId,key:pre}:null));}
  preId++;
 };
 const exchange=async()=>{
  if(targetStarts){await decrypt(peerCipher,await packet(targetCipher,Buffer.from('target start')));await decrypt(targetCipher,await packet(peerCipher,Buffer.from('peer reply')));}
  else {await decrypt(targetCipher,await packet(peerCipher,Buffer.from('peer start')));await decrypt(peerCipher,await packet(targetCipher,Buffer.from('target reply')));}
  for(let i=0;i<3;i++){await decrypt(targetCipher,await packet(peerCipher,Buffer.from(`peer ${i}`)));await decrypt(peerCipher,await packet(targetCipher,Buffer.from(`target ${i}`)));}
 };
 await establish();
 if(mode==='pending')return {target,peer,peerCipher,targetCipher,incoming:[],jid};
 let archived;
 if(mode==='archived-prekey'){
  await decrypt(targetCipher,await packet(peerCipher,Buffer.from('old prekey session')));
  archived=await packet(peerCipher,Buffer.from('delayed archived prekey'));
  targetStarts=true;await establish();await exchange();
 }else{
  await exchange();
  if(mode==='archived'){
   archived=await packet(peerCipher,Buffer.from('delayed archived message'));
   await establish();await exchange();
  }
 }
 const incoming=[];
 for(let i=0;i<4;i++)incoming.push(await packet(peerCipher,Buffer.from([0,255,i,17])));
 await decrypt(targetCipher,incoming[3]);incoming.pop();
 if(archived)incoming.push(archived);
 return {target,peer,peerCipher,targetCipher,incoming,jid};
}
async function context(r,mode,oneTime,targetStarts=true,{tiedClock=false}={}){
 // A strictly increasing synthetic clock prevents the source implementation
 // from selecting an older archive first on equal-millisecond usage times.
 const original=Date.now;let clock=1700000000000;Date.now=()=>tiedClock?clock:++clock;
 try{return await buildContext(r,mode,oneTime,targetStarts);}finally{Date.now=original;}
}
module.exports={context,packet,decrypt,peerAddress,targetAddress,jid};
