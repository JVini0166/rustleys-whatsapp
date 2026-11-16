const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {setup}=require('./group-reference.cjs');
(async()=>{
 const r=await setup(process.argv[2]),cases=[];
 for(const peer of [{group:'synthetic@g.us',jid:'synthetic-sender:1@s.whatsapp.net',user:'synthetic-sender',device:1},{group:'synthetic@g.us',jid:'synthetic-sender:99@hosted.lid',user:'synthetic-sender_129',device:99}]){
  const sender=r.store(),receiver=r.store(),name=r.name(peer.group,peer.user,peer.device),builder=new r.GroupSessionBuilder(sender);
  const distribution=await builder.create(name);await new r.GroupSessionBuilder(receiver).process(name,new r.SenderKeyDistributionMessage(null,null,null,null,distribution.serialize()));
  const cipher=new r.GroupCipher(sender,name),decoder=new r.GroupCipher(receiver,name),packets=[];
  for(const length of [0,1,15,16,17,64,255,4096]){
   const plaintext=Buffer.from(Array.from({length},(_,i)=>(length+i*37)&255)),ciphertext=await cipher.encrypt(plaintext);
   assert.deepEqual(await decoder.decrypt(ciphertext),plaintext);const parsed=new r.SenderKeyMessage(null,null,null,null,ciphertext);
   packets.push({plaintext:Array.from(plaintext),ciphertext:Array.from(ciphertext),iteration:parsed.getIteration()});
  }
  assert.deepEqual(packets.map(p=>p.iteration),[0,2,4,6,8,10,12,14]);
  const legacy=r.store(),legacyCipher=new r.GroupCipher(legacy,name);await new r.GroupSessionBuilder(legacy).process(name,distribution);assert.deepEqual(await legacyCipher.decrypt(Buffer.from(packets[7].ciphertext)),Buffer.from(packets[7].plaintext));
  let legacyError;try{await legacyCipher.decrypt(Buffer.from(packets[0].ciphertext));}catch(error){legacyError=error.message;}
  assert.equal(legacyError,'Expected Buffer instead of: Object');
  cases.push({group:peer.group,author:peer.jid,name:name.toString(),distribution:Array.from(distribution.serialize()),packets,legacy_storage_reordering_error:legacyError});
 }
 const names=[];for(const group of ['', 'synthetic@g.us','x'.repeat(400),'Grupo 🧭😀','日本語','x\0y'])for(const sender of ['synthetic','some_129','用户😀',''])for(const device of [0,1,99,4294967295]){const name=r.name(group,sender,device);names.push({group,sender,device,serialized:name.serialize(),hash:name.hashCode(),equal_clone:name.equals(r.name(group,sender,device)),equal_null:name.equals(null)});}
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/group-upstream.json'),JSON.stringify({upstream_commit:r.commit,synthetic_data:true,cases,names})+'\n');console.log('16 original group messages and 2 sender-key distributions, including Baileys iteration progression');
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
