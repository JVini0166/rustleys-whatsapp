// Development-only libsignal-node v6 peer; never use real account keys.
const fs=require('node:fs'),path=require('node:path'),ts=require('typescript'),signal=require('libsignal');
const {loadReference}=require('./reference.cjs');
async function setup(upstream){
 const r=await loadReference(upstream),ast=ts.createSourceFile('generics.ts',r.source('src/Utils/generics.ts'),ts.ScriptTarget.Latest,true);
 const source=ast.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.name.getText(ast)==='BufferJSON')).map(s=>s.getText(ast)).join('\n');
 const {BufferJSON}=r.compile(source,require),fixture=JSON.parse(fs.readFileSync(path.join(__dirname,'../tests/fixtures/auth-upstream.json')));
 const credentials=fixture.credentials.map(row=>JSON.parse(row.serialized,BufferJSON.reviver));
 return {...r,BufferJSON,credentials,credentialJson:fixture.credentials.map(row=>row.serialized)};
}
const tagged=bytes=>Buffer.concat([Buffer.from([5]),Buffer.from(bytes).subarray(-32)]);
function storage(creds){
 const sessions=new Map(),prekeys=new Map();
 return {sessions,prekeys,removed:[],
  loadSession:async id=>sessions.has(id)?signal.SessionRecord.deserialize(sessions.get(id)):null,
  storeSession:async(id,record)=>{sessions.set(id,record.serialize());},
  isTrustedIdentity:()=>true,
  getOurIdentity:()=>({pubKey:tagged(creds.signedIdentityKey.public),privKey:Buffer.from(creds.signedIdentityKey.private)}),
  getOurRegistrationId:()=>creds.registrationId,
  loadSignedPreKey:()=>({pubKey:tagged(creds.signedPreKey.keyPair.public),privKey:Buffer.from(creds.signedPreKey.keyPair.private)}),
  loadPreKey:async id=>{const key=prekeys.get(id);return key?{pubKey:tagged(key.public),privKey:Buffer.from(key.private)}:undefined;},
  removePreKey:async function(id){prekeys.delete(id);this.removed.push(id);}
 };
}
function bundle(creds,prekey){return {registrationId:creds.registrationId,identityKey:tagged(creds.signedIdentityKey.public),signedPreKey:{keyId:creds.signedPreKey.keyId,publicKey:tagged(creds.signedPreKey.keyPair.public),signature:Buffer.from(creds.signedPreKey.signature)},...(prekey?{preKey:{keyId:prekey.id,publicKey:tagged(prekey.key.public)}}:{})};}
module.exports={setup,storage,bundle,tagged,signal};
