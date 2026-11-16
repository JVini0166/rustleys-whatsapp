const fs=require('node:fs'),path=require('node:path'),ts=require('typescript');
const {loadReference}=require('./reference.cjs');
(async()=>{
 const r=await loadReference(process.argv[2]),jids=r.compile(r.source('src/WABinary/jid-utils.ts'),require);
 const ast=ts.createSourceFile('libsignal.ts',r.source('src/Signal/libsignal.ts'),ts.ScriptTarget.Latest,true);
 const declaration=ast.statements.find(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(ast)==='jidToSignalProtocolAddress')).getText(ast);
 const {address}=r.compile("const libsignal=require('libsignal');const {jidDecode,WAJIDDomains}=require('../WABinary');\n"+declaration+'\nmodule.exports.address=jidToSignalProtocolAddress;',n=>n==='../WABinary'?jids:require(n));
 const cases=[];for(const user of ['123','synthetic','invalid.name',''])for(const server of ['s.whatsapp.net','c.us','lid','hosted','hosted.lid','g.us'])for(const agent of [undefined,0,1,8,128,129])for(const device of [undefined,0,1,99,4294967295]){
  const jid=jids.jidEncode(user,server,device,agent);try{cases.push({jid,address:address(jid).toString()});}catch{cases.push({jid,error:true});}
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/signal-address-upstream.json'),JSON.stringify({upstream_commit:r.commit,cases})+'\n');console.log(`${cases.length} addresses from the original Baileys repository helper`);
})().catch(e=>{console.error(e.message);process.exitCode=1;});
