// Offline group interoperability with the actual pinned Baileys TS modules.
const fsp=require('node:fs').promises,path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {setup}=require('./group-reference.cjs');
const {buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{
 const root=path.join(__dirname,'..'),r=await setup(process.argv[2]),executable=buildDriver(root,'signal_crosscheck');
 const fixture=JSON.parse(await fsp.readFile(path.join(root,'tests/fixtures/auth-upstream.json'),'utf8')),credentials=JSON.parse(fixture.credentials[0].serialized);
 // Characterize the real legacy signalStorage serializer before using a
 // correctly typed BufferJSON store to test the unchanged group primitives.
 {const a=r.store(),b=r.store(),name=r.name('legacy-regression@g.us','synthetic',1);const dist=await new r.GroupSessionBuilder(a).create(name);await new r.GroupSessionBuilder(b).process(name,dist);const send=new r.GroupCipher(a,name),receive=new r.GroupCipher(b,name);const first=await send.encrypt(Buffer.from('first')),later=await send.encrypt(Buffer.from('later'));await receive.decrypt(later);await assert.rejects(receive.decrypt(first),/Expected Buffer instead of: Object/);}
 const temp=await fsp.mkdtemp(path.join(os.tmpdir(),'rustleys-group-interop-'));let current,messages=0,operations=0;
 try{
  for(const direction of ['node-to-rust','rust-to-node'])for(const author of [{jid:'synthetic-sender:1@s.whatsapp.net',name:'synthetic-sender',device:1},{jid:'synthetic-sender:99@hosted.lid',name:'synthetic-sender_129',device:99}]){
   const db=path.join(temp,`${direction}-${author.device}.sqlite`),group='synthetic@g.us',name=r.name(group,author.name,author.device),store=r.store('buffer-json'),builder=new r.GroupSessionBuilder(store),cipher=new r.GroupCipher(store,name);
   current=startDriver(executable,[db],root);const request=data=>{operations++;return current.request(data);};const command=(cmd,data={})=>request({command:cmd,group,author:author.jid,...data});await request({command:'configure',credentials});
   const packets=[],distribution=(bytes)=>new r.SenderKeyDistributionMessage(null,null,null,null,Buffer.from(bytes));
   if(direction==='node-to-rust'){
    const initial=await builder.create(name);await command('group_process',{distribution:Array.from(initial.serialize())});
    for(const length of [0,1,15,16,17,64,255,4096]){
     const plaintext=Buffer.alloc(length,(length+13)&255),dist=await builder.create(name),ciphertext=await cipher.encrypt(plaintext);await command('group_process',{distribution:Array.from(dist.serialize())});packets.push({plaintext,ciphertext:Buffer.from(ciphertext)});
    }
   }else{
    const initial=await command('group_distribution');await builder.process(name,distribution(initial));
    for(const length of [0,1,15,16,17,64,255,4096]){const plaintext=Buffer.alloc(length,(length+17)&255),packet=await command('group_encrypt',{plaintext:Array.from(plaintext)});const parsed=new r.SenderKeyMessage(null,null,null,null,Buffer.from(packet.ciphertext));assert.equal(parsed.getIteration(),packets.length*2);const skdm=distribution(packet.distribution);assert.equal(skdm.getIteration(),packets.length===0?0:packets.length*2-1);packets.push({plaintext,ciphertext:Buffer.from(packet.ciphertext)});}
   }
   const decode=async packet=>direction==='node-to-rust'?Buffer.from(await command('group_decrypt',{ciphertext:Array.from(packet.ciphertext)})):Buffer.from(await cipher.decrypt(packet.ciphertext));
   const corrupt=Buffer.from(packets[0].ciphertext);corrupt[corrupt.length-1]^=1;await assert.rejects(decode({ciphertext:corrupt}));
   for(const index of [7,0,6,1,5,2,4,3]){assert.deepEqual(await decode(packets[index]),packets[index].plaintext);messages++;}
   await assert.rejects(decode(packets[0]));
   await current.close();current=startDriver(executable,[db],root);await request({command:'configure',credentials});
   // Reopened native sending or receiving state must remain in step with JS.
   if(direction==='node-to-rust'){const plaintext=Buffer.from('after native restart'),ciphertext=await cipher.encrypt(plaintext);assert.deepEqual(Buffer.from(await command('group_decrypt',{ciphertext:Array.from(ciphertext)})),plaintext);}
   else{const plaintext=Buffer.from('after native restart'),packet=await command('group_encrypt',{plaintext:Array.from(plaintext)});assert.equal(new r.SenderKeyMessage(null,null,null,null,Buffer.from(packet.ciphertext)).getIteration(),16);assert.deepEqual(await cipher.decrypt(Buffer.from(packet.ciphertext)),plaintext);}
   messages++;
   // A new sender key works while already-consumed messages from the old key stay rejected.
   if(direction==='node-to-rust'){
    store.records.delete(name.toString());const dist=await builder.create(name);await command('group_process',{distribution:Array.from(dist.serialize())});const plaintext=Buffer.from('after sender rekey'),ciphertext=await cipher.encrypt(plaintext);assert.deepEqual(Buffer.from(await command('group_decrypt',{ciphertext:Array.from(ciphertext)})),plaintext);
   }else{
    await command('group_delete');const packet=await command('group_encrypt',{plaintext:Array.from(Buffer.from('after sender rekey'))});await builder.process(name,distribution(packet.distribution));assert.deepEqual(await cipher.decrypt(Buffer.from(packet.ciphertext)),Buffer.from('after sender rekey'));
   }
   messages++;await assert.rejects(decode(packets[0]));await current.close();current=undefined;
  }
  console.log(`${messages} group messages verified in both directions against original Baileys group modules with a typed BufferJSON store across 4 contexts; empty/binary payloads, counters, signatures, reordering, rekeys and native process restarts passed (${operations} Rust operations); original legacy JSON reordering regression reproduced separately`);
 }finally{if(current)await current.kill();await fsp.rm(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
