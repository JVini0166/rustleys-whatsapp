// Original mapping helper versus the native repository, with intentional bug fixes checked separately.
const fsp=require('node:fs').promises,path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {setup}=require('./lid-reference.cjs'),{buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{
 const root=path.join(__dirname,'..'),r=await setup(process.argv[2]),executable=buildDriver(root,'signal_crosscheck');const fixture=JSON.parse(await fsp.readFile(path.join(root,'tests/fixtures/lid-upstream.json'),'utf8')),auth=JSON.parse(await fsp.readFile(path.join(root,'tests/fixtures/auth-upstream.json'),'utf8'));const temp=await fsp.mkdtemp(path.join(os.tmpdir(),'rustleys-lid-interop-'));let current,checks=0;
 try{
  for(let n=0;n<fixture.cases.length;n++){
   const row=fixture.cases[n],original=new r.LIDMappingStore(r.keys(),r.logger);current=startDriver(executable,[path.join(temp,`${n}.sqlite`)],root);const request=data=>current.request(data);await request({command:'configure',credentials:JSON.parse(auth.credentials[0].serialized)});await original.storeLIDPNMappings(row.pairs);await request({command:'mapping_store',pairs:row.pairs});if(n){original.close();await request({command:'mapping_close'});}
   assert.deepEqual(await request({command:'mapping_forward',ids:row.pns}),await original.getLIDsForPNs(row.pns)||[]);assert.deepEqual(await request({command:'mapping_reverse',ids:row.lids}),await original.getPNsForLIDs(row.lids)||[]);checks+=2;
   await original.storeLIDPNMappings([{pn:'pnA@s.whatsapp.net',lid:'lidC@lid'}]);await request({command:'mapping_store',pairs:[{pn:'pnA@s.whatsapp.net',lid:'lidC@lid'}]});original.close();assert.equal(await original.getPNForLID('lidA@lid'),'pnA:0@s.whatsapp.net');assert.deepEqual(await request({command:'mapping_reverse',ids:['lidA@lid']}),[]);checks++;
   await request({command:'mapping_store',pairs:[{pn:'lidZ@lid',lid:'pnZ@s.whatsapp.net'}]});assert.deepEqual(await request({command:'mapping_forward',ids:['pnZ@s.whatsapp.net']}),[{pn:'pnZ@s.whatsapp.net',lid:'lidZ@lid'}]);assert.deepEqual(await request({command:'mapping_reverse',ids:['lidB:99@hosted.lid']}),[{pn:'pnB:99@hosted',lid:'lidB:99@hosted.lid'}]);checks+=2;original.close();await current.close();current=undefined;
  }
  console.log(`${checks} mapping comparisons/regression checks passed against original PN/LID modules; native stale-reverse cleanup, swapped fields and hosted reverse behavior verified separately`);
 }finally{if(current)await current.kill();await fsp.rm(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
