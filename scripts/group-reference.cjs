// Development-only loader for the exact pinned Baileys group implementation.
const ts=require('typescript'),signal=require('libsignal');
const {loadReference}=require('./reference.cjs');
async function setup(upstream){
 const r=await loadReference(upstream),ast=ts.createSourceFile('generics.ts',r.source('src/Utils/generics.ts'),ts.ScriptTarget.Latest,true);
 const declaration=ast.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(ast)==='BufferJSON')).map(s=>s.getText(ast)).join('\n');
 const {BufferJSON}=r.compile(declaration,require),cache={};
 function load(name){return cache[name]??(cache[name]=r.compile(r.source(`src/Signal/Group/${name}.ts`),n=>n.startsWith('./')?load(n.slice(2)):n==='../../../WAProto/index.js'?{proto:r.proto}:n==='../../Utils/generics'?{BufferJSON}:require(n)));}
 const group={...load('group_cipher'),...load('group-session-builder'),...load('sender-key-record'),...load('sender-key-name'),...load('sender-key-message'),...load('sender-key-distribution-message')};
 const store=(format="legacy")=>{const records=new Map();return {records,loadSenderKey:async name=>records.has(name.toString())?group.SenderKeyRecord.deserialize(records.get(name.toString())):new group.SenderKeyRecord(),storeSenderKey:async(name,record)=>{records.set(name.toString(),Buffer.from(JSON.stringify(record.serialize(),format==="buffer-json"?BufferJSON.replacer:undefined)));}};};
 const name=(groupId,user,device)=>new group.SenderKeyName(groupId,new signal.ProtocolAddress(user,device));
 return {...r,...group,BufferJSON,store,name};
}
module.exports={setup};
