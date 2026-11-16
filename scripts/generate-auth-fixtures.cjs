// Synthetic credentials only, generated offline by the actual pinned source.
const fs=require('node:fs'),path=require('node:path'),ts=require('typescript');
const {loadReference}=require('./reference.cjs');
(async()=>{
 const r=await loadReference(process.argv[2]);
 function declarations(file,names){const ast=ts.createSourceFile(file,r.source(file),ts.ScriptTarget.Latest,true);return ast.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>names.includes(d.name.getText(ast)))).map(s=>s.getText(ast)).join('\n');}
 const genericSource=declarations('src/Utils/generics.ts',['BufferJSON','generateRegistrationId']);
 let seed=0;
 const generics=r.compile("const {randomBytes}=require('crypto');\n"+genericSource,n=>n==='crypto'?{randomBytes:len=>Buffer.from(Array.from({length:len},(_,i)=>(seed+i*37)&255))}:require(n));
 const authSource=declarations('src/Utils/auth-utils.ts',['initAuthCreds','assertMeId']);
 const auth=r.compile("const {Curve,signedKeyPair}=require('./crypto'); const {randomBytes}=require('crypto'); const {generateRegistrationId}=require('./generics'); const {Boom}=require('@hapi/boom');\n"+authSource,n=>n==='./crypto'?r.crypto:n==='./generics'?generics:n==='crypto'?{randomBytes:len=>Buffer.from(Array.from({length:len},(_,i)=>(seed+i*37)&255))}:require(n));
 const credentials=[];for(seed=0;seed<8;seed++){
  const creds=auth.initAuthCreds();
  if(seed%2){creds.me={id:`synthetic-${seed}:1@s.whatsapp.net`,name:'Synthetic contact',phoneNumber:'synthetic'};creds.routingInfo=Buffer.from([1,2,3,seed]);creds.additionalData={futureField:'retained'};creds.futureCredentialField={value:seed};creds.signalIdentities=[{identifier:{name:'synthetic',deviceId:0},identifierKey:Buffer.concat([Buffer.from([5]),Buffer.from(creds.signedIdentityKey.public)])}];creds.processedHistoryMessages=[{key:{id:'offline',remoteJid:'synthetic@s.whatsapp.net',fromMe:false},messageTimestamp:{low:7,high:0,unsigned:true}}];}
  let me;try{me=auth.assertMeId(creds);}catch{me=null;}
  credentials.push({serialized:JSON.stringify(creds,generics.BufferJSON.replacer),me});
 }
 const registration=[];for(seed=0;seed<256;seed++)registration.push({bytes:[seed,(seed+37)&255],result:generics.generateRegistrationId()});
 const bytes=[];for(const data of [Buffer.alloc(0),Buffer.from([0]),Buffer.from([0,1,127,128,255]),Buffer.from(Array.from({length:256},(_,i)=>i))]){
  const serialized=JSON.stringify(data,generics.BufferJSON.replacer);
  bytes.push({serialized,data:Array.from(generics.BufferJSON.reviver('',JSON.parse(serialized)))});
  const legacy=Object.fromEntries(Array.from(data,(v,i)=>[String(i),v]));if(data.length)bytes.push({serialized:JSON.stringify(legacy),data:Array.from(generics.BufferJSON.reviver('',legacy))});
 }
 const result={upstream_commit:r.commit,synthetic_data:true,credentials,registration,bytes};
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/auth-upstream.json'),JSON.stringify(result)+'\n');
 console.log(`${credentials.length} original credential states, ${registration.length} registration vectors, ${bytes.length} BufferJSON cases`);
})().catch(e=>{console.error(e);process.exitCode=1;});
