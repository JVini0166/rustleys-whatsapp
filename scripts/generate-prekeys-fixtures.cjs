const fs=require('node:fs'),path=require('node:path');const {setup,keyStore}=require('./prekeys-reference.cjs');const {nodeToJson}=require('./pairing-reference.cjs');
(async()=>{const r=await setup(process.argv[2]),cases=[];
 for(const [first,next,count]of [[1,1,5],[10,20,5],[10,20,12],[0,0,1],[0xfffffd,0xfffffd,3]]){
 const creds={...r.credentials[0],nextPreKeyId:next,firstUnuploadedPreKeyId:first},existing={};for(let id=first;id<next;id++)existing[id]=r.crypto.Curve.generateKeyPair();const store=keyStore(existing);
 const result=await r.getNextPreKeysNode({creds,keys:store},count);
 cases.push({credentials:JSON.parse(JSON.stringify(creds,r.BufferJSON.replacer)),first,next,count,update:result.update,node:nodeToJson(result.node),wire:Array.from(r.binary.encodeBinaryNode(result.node)),keys:JSON.parse(JSON.stringify(store.rows,r.BufferJSON.replacer))});
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/prekeys-upstream.json'),JSON.stringify({upstream_commit:r.commit,synthetic_data:true,cases},null,2)+'\n');console.log(`${cases.length} original prekey planning/upload fixtures generated, including reused ranges and 24-bit boundary`);
})().catch(error=>{console.error(error.message);process.exitCode=1;});
