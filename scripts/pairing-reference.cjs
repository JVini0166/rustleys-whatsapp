// Exact pinned Baileys functions, compiled as a development-only oracle.
const ts=require('typescript');const {setup}=require('./signal-reference.cjs');
async function reference(upstream){
 const r=await setup(upstream),defaults=ts.createSourceFile('defaults.ts',r.source('src/Defaults/index.ts'),ts.ScriptTarget.Latest,true),names=new Set(['WA_ADV_ACCOUNT_SIG_PREFIX','WA_ADV_DEVICE_SIG_PREFIX','WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX']);
 const prefixes=r.compile(defaults.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>names.has(d.name.getText(defaults)))).map(s=>s.getText(defaults)).join('\n'),require);
 const utils=r.compile(r.source('src/WABinary/generic-utils.ts'),n=>n==='../../WAProto/index.js'?{proto:r.proto}:require(n));
 const jid=r.compile(r.source('src/WABinary/jid-utils.ts'),require);
 const tree=ts.createSourceFile('signal.ts',r.source('src/Utils/signal.ts'),ts.ScriptTarget.Latest,true);
 // Isolated original function references the module's imported public-key helper.
 const source=tree.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(tree)==='createSignalIdentity')).map(s=>s.getText(tree)).join('\n');
 const identityFn=r.compile('const generateSignalPubKey = require("./crypto").generateSignalPubKey;\n'+source,n=>n==='./crypto'?r.crypto:require(n));
 const genericTree=ts.createSourceFile('generics.ts',r.source('src/Utils/generics.ts'),ts.ScriptTarget.Latest,true);
 const generics=r.compile(genericTree.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(genericTree)==='encodeBigEndian')).map(s=>s.getText(genericTree)).join('\n'),require);
 const validation=r.compile(r.source('src/Utils/validate-connection.ts'),n=>n==='../../WAProto/index.js'?{proto:r.proto}:n==='../Defaults'?{...r.constants,...prefixes}:n==='../WABinary'?{...utils,...jid}:n==='./crypto'?r.crypto:n==='./generics'?generics:n==='./signal'?identityFn:require(n));
 const companion=r.compile(r.source('src/Utils/companion-reg-client-utils.ts'),require);
 return {...r,...validation,...companion,prefixes};
}
const nodeToJson=node=>({tag:node.tag,attrs:node.attrs,content:Buffer.isBuffer(node.content)||node.content instanceof Uint8Array?{bytes:Array.from(node.content)}:Array.isArray(node.content)?node.content.map(nodeToJson):node.content??null});
const nodeFromJson=node=>({tag:node.tag,attrs:node.attrs,content:node.content&&node.content.bytes?Buffer.from(node.content.bytes):Array.isArray(node.content)?node.content.map(nodeFromJson):node.content??undefined});
module.exports={reference,nodeToJson,nodeFromJson};
