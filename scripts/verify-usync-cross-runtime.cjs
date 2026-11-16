const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {reference,normalize}=require('./usync-reference.cjs'),{nodeFromJson,nodeToJson}=require('./pairing-reference.cjs'),{buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{const r=await reference(process.argv[2]),root=path.join(__dirname,'..'),fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/usync-upstream.json')));assert.equal(fixture.upstream_commit,r.commit);
 const exe=buildDriver(root,'usync_crosscheck'),driver=startDriver(exe,[],root);let builds=0,parsers=0,results=0,helpers=0;
 const clean=v=>JSON.parse(JSON.stringify(normalize(v))??'null');
 try{
  for(const row of fixture.builds){if(row.error){await assert.rejects(driver.request({command:'build',...row}));continue;}const wire=await driver.request({command:'build',...row});const native=r.binary.decodeBinaryNode(Buffer.from(wire));let captured;await r.methods(async n=>{captured=n;},row.sid).executeUSyncQuery(r.make(row.config));assert.deepEqual(nodeToJson(native),nodeToJson(r.binary.decodeBinaryNode(r.binary.encodeBinaryNode(captured))));assert.deepEqual(Buffer.from(wire),r.binary.encodeBinaryNode(captured));builds++;}
  for(const row of fixture.parsers){let expected;try{expected=clean(new r.classes[row.protocol]().parser(nodeFromJson(row.node)));}catch{await assert.rejects(driver.request({command:'protocol',...row}));parsers++;continue;}assert.deepEqual(await driver.request({command:'protocol',...row}),expected);parsers++;}
  for(const row of fixture.results){let expected;try{expected=clean(r.make(row.config).parseUSyncQueryResult(nodeFromJson(row.node)));}catch{await assert.rejects(driver.request({command:'parse',...row}));results++;continue;}assert.deepEqual(await driver.request({command:'parse',...row}),expected);results++;}
  for(const row of fixture.differences){
   if(row.original_error)assert.throws(()=>r.make(row.config).parseUSyncQueryResult(nodeFromJson(row.node)));
   else assert.deepEqual(clean(r.make(row.config).parseUSyncQueryResult(nodeFromJson(row.node))),row.original);
   assert.deepEqual(await driver.request({command:'parse',...row}),row.native);
  }
  // Independent numeric coercion corpus, including large radix integers.
  let seed=0x1234abcd;const next=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
  for(let i=0;i<160;i++){
   const base=[2,8,16][i%3],prefix={2:'0b',8:'0o',16:'0x'}[base],length=1+next()%350;
   let value=prefix;for(let j=0;j<length;j++)value+=(next()%base).toString(base);
   const input={tag:'devices',attrs:{},content:[{tag:'device-list',attrs:{},content:[{tag:'device',attrs:{id:value,'key-index':value,is_hosted:'true'}}]}]};
   const expected=clean(new r.classes.devices().parser(input));
   assert.deepEqual(await driver.request({command:'protocol',protocol:'devices',node:nodeToJson(input)}),expected,`Numeric coercion: ${value}`);parsers++;
  }
  const response=fixture.results[0].node,phones=['+5511999999999:4@s.whatsapp.net','999@lid','123@lid','12345@s.whatsapp.net','a+b+c'],jids=['123@s.whatsapp.net','999@lid','456@s.whatsapp.net'];
  for(const request of [{command:'execute',config:fixture.builds[9].config},{command:'on_whatsapp',phones},{command:'on_whatsapp',phones:['9@lid']},{command:'on_whatsapp',phones:[]},{command:'pn_from_lid',jids},{command:'pn_from_lid',jids:['9@lid']},{command:'pn_from_lid',jids:[]}]){
   for(const reply of [response,{tag:'iq',attrs:{type:'result'},content:null},{tag:'iq',attrs:{type:'error'},content:null}]){
    const native=await driver.request({...request,response:reply});let captured=[];const methods=r.methods(async n=>{captured.push(n);return nodeFromJson(reply);},native.sids[0]??'unused');let expected;
    if(request.command==='execute')expected=await methods.executeUSyncQuery(r.make(request.config));else if(request.command==='on_whatsapp')expected=await methods.onWhatsApp(...request.phones);else expected=await methods.pnFromLIDUSync(request.jids);
    assert.deepEqual(native.value,clean(expected));assert.deepEqual(native.wire,captured.map(n=>Array.from(r.binary.encodeBinaryNode(n))));helpers++;
   }
  }
  console.log(`${builds} exact original USync query wires, ${parsers} original protocol parser cases, ${results} aggregate results and ${helpers} asynchronous socket/helper flows and ${fixture.differences.length} explicit inherited-property safety differences passed against native Rust`);
 }finally{await driver.close();}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
