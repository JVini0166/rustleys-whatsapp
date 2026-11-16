// Original pinned USync classes and nested socket methods; dev oracle only.
const ts=require('typescript'),path=require('node:path');
const {setup}=require('./signal-reference.cjs');
async function reference(upstream){
 const r=await setup(upstream),cache={};
 const utils=r.compile(r.source('src/WABinary/generic-utils.ts'),n=>n==='../../WAProto/index.js'?{proto:r.proto}:require(n));
 const jid=r.compile(r.source('src/WABinary/jid-utils.ts'),require);
 function load(file){if(cache[file])return cache[file];const m=r.compile(r.source(file),n=>{if(n.endsWith('/WABinary'))return {...r.binary,...utils,...jid};if(n.startsWith('.')){let next=path.posix.normalize(path.posix.join(path.posix.dirname(file),n));if(next.endsWith('/Protocols'))next+='/index';return load(next+'.ts');}return require(n);});return cache[file]=m;}
 const {USyncQuery}=load('src/WAUSync/USyncQuery.ts'),{USyncUser}=load('src/WAUSync/USyncUser.ts');
 const classes={contact:load('src/WAUSync/Protocols/USyncContactProtocol.ts').USyncContactProtocol,devices:load('src/WAUSync/Protocols/USyncDeviceProtocol.ts').USyncDeviceProtocol,status:load('src/WAUSync/Protocols/USyncStatusProtocol.ts').USyncStatusProtocol,disappearing_mode:load('src/WAUSync/Protocols/USyncDisappearingModeProtocol.ts').USyncDisappearingModeProtocol,bot:load('src/WAUSync/Protocols/UsyncBotProfileProtocol.ts').USyncBotProfileProtocol,lid:load('src/WAUSync/Protocols/UsyncLIDProtocol.ts').USyncLIDProtocol,username:load('src/WAUSync/Protocols/USyncUsernameProtocol.ts').USyncUsernameProtocol};
 const tree=ts.createSourceFile('socket.ts',r.source('src/Socket/socket.ts'),ts.ScriptTarget.Latest,true),decls={};
 function walk(n){if(ts.isVariableDeclaration(n)&&['executeUSyncQuery','onWhatsApp','pnFromLIDUSync'].includes(n.name.getText(tree)))decls[n.name.getText(tree)]=n.getText(tree);ts.forEachChild(n,walk);}walk(tree);
 function methods(query,sid){const inputs={query,generateMessageTag:()=>sid,S_WHATSAPP_NET:'@s.whatsapp.net',USyncQuery,USyncUser,isLidUser:jid.isLidUser,logger:{warn(){}}};return r.compile('const {query,generateMessageTag,S_WHATSAPP_NET,USyncQuery,USyncUser,isLidUser,logger}=require("inputs");\n'+Object.values(decls).map(d=>'export const '+d).join('\n'),n=>n==='inputs'?inputs:require(n));}
 function make(config){const q=new USyncQuery();q.protocols=config.protocols.map(p=>new classes[p]());q.users=(config.users||[]).map(u=>Object.assign(new USyncUser(),u));if(config.mode!==undefined)q.withMode(config.mode);if(config.context!==undefined)q.withContext(config.context);return q;}
 return {...r,classes,make,methods};
}
function normalize(value){if(value instanceof Date)return value.getTime();if(Buffer.isBuffer(value)||value instanceof Uint8Array)return Array.from(value);if(Array.isArray(value))return value.map(normalize);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).filter(([,v])=>v!==undefined).map(([k,v])=>[k,normalize(v)]));return value;}
module.exports={reference,normalize};
