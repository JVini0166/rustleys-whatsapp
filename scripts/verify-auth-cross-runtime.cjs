// Executes the actual pinned useMultiFileAuthState helper against temporary
// synthetic folders, then checks Rust exports through that same JS helper.
const fs=require('node:fs'),fsp=fs.promises,os=require('node:os'),path=require('node:path'),ts=require('typescript'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const {loadReference}=require('./reference.cjs');
(async()=>{
 const root=path.join(__dirname,'..'),r=await loadReference(process.argv[2]);
 const ast=ts.createSourceFile('generics.ts',r.source('src/Utils/generics.ts'),ts.ScriptTarget.Latest,true);
 const bufferSource=ast.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(ast)==='BufferJSON')).map(s=>s.getText(ast)).join('\n');
 const {BufferJSON}=r.compile(bufferSource,require);
 const {useMultiFileAuthState}=r.compile(r.source('src/Utils/use-multi-file-auth-state.ts'),n=>n==='./auth-utils'?{initAuthCreds:()=>{throw Error('unexpected credential reset')}}:n==='./generics'?{BufferJSON}:n==='../../WAProto/index.js'?{proto:r.proto}:require(n));
 const temp=await fsp.mkdtemp(path.join(os.tmpdir(),'rustleys-auth-interop-'));
 try{
  const input=path.join(temp,'original'),output=path.join(temp,'rust');await fsp.mkdir(input);
  const fixture=JSON.parse(await fsp.readFile(path.join(root,'tests/fixtures/auth-upstream.json'),'utf8'));
  await fsp.writeFile(path.join(input,'creds.json'),fixture.credentials[1].serialized);
  const original=await useMultiFileAuthState(input);
  const b=Buffer.from([0,1,2,255]),data={
   'pre-key':original.state.creds.signedPreKey.keyPair,session:b,'sender-key':b,'sender-key-memory':{'synthetic@s.whatsapp.net':true},
   'app-state-sync-key':r.proto.Message.AppStateSyncKeyData.fromObject({keyData:b,fingerprint:{rawId:7,currentIndex:1,deviceIndexes:[1,2]},timestamp:'1794800000000'}),
   'app-state-sync-version':{version:2,hash:Buffer.alloc(128),indexValueMap:{AA:{valueMac:b}}},'lid-mapping':'synthetic@lid','device-list':['synthetic:1@s.whatsapp.net'],
   tctoken:{token:b,timestamp:'1794800000',senderTimestamp:1794800000},'identity-key':b
  };
  await original.state.keys.set(Object.fromEntries(Object.entries(data).map(([k,v])=>[k,{'synthetic/1:2':v}])));await original.saveCreds();
  const cargo=spawnSync('cargo',['run','--locked','--quiet','--example','auth_crosscheck','--',input,output],{cwd:root,env:{...process.env,CARGO_BUILD_JOBS:'1'},encoding:'utf8',maxBuffer:2*1024*1024});
  if(cargo.status!==0)throw Error(cargo.stderr||'Rust auth driver failed');
  const copied=await useMultiFileAuthState(output);
  const norm=value=>JSON.parse(JSON.stringify(value,BufferJSON.replacer));
  assert.deepEqual(norm(copied.state.creds),norm(original.state.creds));
  for(const category of Object.keys(data))assert.deepEqual(norm(await copied.state.keys.get(category,['synthetic/1:2','missing'])),norm(await original.state.keys.get(category,['synthetic/1:2','missing'])),category);
  const fresh=await useMultiFileAuthState(path.join(output,'fresh'));const curve=require('libsignal/src/curve');
  for(const pair of [fresh.state.creds.noiseKey,fresh.state.creds.pairingEphemeralKeyPair,fresh.state.creds.signedIdentityKey,fresh.state.creds.signedPreKey.keyPair])assert.deepEqual(Buffer.from(curve.getPublicFromPrivateKey(pair.private)).subarray(-32),Buffer.from(pair.public));
  assert(curve.verifySignature(Buffer.concat([Buffer.from([5]),Buffer.from(fresh.state.creds.signedIdentityKey.public)]),Buffer.concat([Buffer.from([5]),Buffer.from(fresh.state.creds.signedPreKey.keyPair.public)]),fresh.state.creds.signedPreKey.signature));
  assert.equal(Buffer.from(fresh.state.creds.advSecretKey,'base64').length,32);
  console.log('Original JS multi-file adapter → Rust → original JS: credentials and all 10 key categories match; fresh Rust credentials validate with libsignal-node');
 }finally{await fsp.rm(temp,{recursive:true,force:true});}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
