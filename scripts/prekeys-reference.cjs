const ts=require('typescript');const {reference}=require('./pairing-reference.cjs');
async function setup(upstream,generate){
 const r=await reference(upstream),ast=ts.createSourceFile('signal.ts',r.source('src/Utils/signal.ts'),ts.ScriptTarget.Latest,true),names=new Set(['getPreKeys','generateOrGetPreKeys','xmppPreKey','xmppSignedPreKey','getNextPreKeys','getNextPreKeysNode']);
 const original=ast.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>names.has(d.name.getText(ast)))).map(s=>s.getText(ast)).join('\n');
 const genericAst=ts.createSourceFile('generics.ts',r.source('src/Utils/generics.ts'),ts.ScriptTarget.Latest,true),generics=r.compile(genericAst.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(genericAst)==='encodeBigEndian')).map(s=>s.getText(genericAst)).join('\n'),require);
 const jid=r.compile(r.source('src/WABinary/jid-utils.ts'),require);
 const deps={...jid,Curve:{...r.crypto.Curve,...(generate?{generateKeyPair:generate}:{})},...generics,...r.constants};
 const functions=r.compile('const {Curve,encodeBigEndian,KEY_BUNDLE_TYPE,S_WHATSAPP_NET}=require("oracle-inputs");\n'+original,n=>n==='oracle-inputs'?deps:require(n));
 return {...r,...functions};
}
function keyStore(initial={}){const rows={...initial};return {rows,async get(type,ids){return Object.fromEntries(ids.map(id=>[id,rows[id]??null]));},async set(values){Object.assign(rows,values['pre-key']);}};}
module.exports={setup,keyStore};
