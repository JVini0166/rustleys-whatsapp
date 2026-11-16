const {setup:groupSetup}=require('./group-reference.cjs');
async function setup(upstream){
 const r=await groupSetup(upstream),jids=r.compile(r.source('src/WABinary/jid-utils.ts'),require);
 const {LIDMappingStore}=r.compile(r.source('src/Signal/lid-mapping.ts'),n=>n==='../WABinary'?jids:require(n));
 const {makeLibSignalRepository}=r.compile(r.source('src/Signal/libsignal.ts'),n=>n==='../WABinary'?jids:n==='../Utils'?{generateSignalPubKey:r.crypto.generateSignalPubKey}:n==='./lid-mapping'?{LIDMappingStore}:n==='./Group'?r:n==='./Group/sender-key-name'?{SenderKeyName:r.SenderKeyName}:n==='./Group/sender-key-record'?{SenderKeyRecord:r.SenderKeyRecord}:require(n));
 const logger={trace(){},debug(){},info(){},warn(){},error(){},level:'silent'};
 function keys(initial={}){const data=structuredClone(initial);return {data,get:async(type,ids)=>Object.fromEntries(ids.filter(id=>data[type]?.[id]!=null).map(id=>[id,data[type][id]])),set:async changes=>{for(const [type,values] of Object.entries(changes)){data[type]??={};for(const [id,value] of Object.entries(values)){if(value===null)delete data[type][id];else data[type][id]=value;}}},transaction:async work=>work(),isInTransaction:()=>false};}
 return {...r,jids,LIDMappingStore,makeLibSignalRepository,logger,keys};
}
module.exports={setup};
