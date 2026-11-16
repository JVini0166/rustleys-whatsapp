// Synthetic public test data only; no production sessions or credentials.
const fs=require('node:fs'),path=require('node:path'),{execFileSync}=require('node:child_process');
const ts=require('typescript');
(async()=>{
 const upstream=process.argv[2],expected=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/upstream-inventory.json'))).commit;
 if(!upstream||execFileSync('git',['-C',upstream,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==expected)throw Error('Expected pinned upstream');
 const bridge=await import('whatsapp-rust-bridge');
 const source=execFileSync('git',['-C',upstream,'show',`${expected}:src/Utils/crypto.ts`],{encoding:'utf8'});
 const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 const m={exports:{}};new Function('require','module','exports',js)(n=>n==='whatsapp-rust-bridge'?bridge:n==='../Defaults'?{KEY_BUNDLE_TYPE:Buffer.from([5])}:require(n),m,m.exports);const c=m.exports;
 const buf=(len,seed)=>Buffer.from(Array.from({length:len},(_,i)=>(seed+i*73)&255)),arr=b=>Array.from(b);
 const cases=[];
 for(const length of [0,1,15,16,17,31,32,63,64,255,256,1024,4096]) {
  const data=buf(length,length+3),key=buf(32,length),iv=buf(16,length+1),nonce=buf(12,length+2),aad=buf(length%17,length+4);
  cases.push({data:arr(data),key:arr(key),iv:arr(iv),nonce:arr(nonce),aad:arr(aad),cbc:arr(c.aesEncrypWithIV(data,key,iv)),ctr:arr(c.aesEncryptCTR(data,key,iv)),gcm:arr(c.aesEncryptGCM(data,key,nonce,aad)),sha256:arr(c.sha256(data)),md5:arr(c.md5(data)),hmac256:arr(c.hmacSign(data,key)),hmac512:arr(c.hmacSign(data,key,'sha512'))});
 }
 const derivations=[];
 for(const length of [0,1,32,64,512,8160])for(const salt of [undefined,Buffer.alloc(0),buf(32,9)]) {
  const input=buf(33,12),info='WhatsApp Synthetic Test';derivations.push({input:arr(input),length,salt:salt?arr(salt):null,info,result:arr(c.hkdf(input,length,{salt,info}))});
 }
 const curve=require('libsignal/src/curve'),agreements=[];
 for(let seed=0;seed<16;seed++) {
  const privateKey=buf(32,seed),peerPrivate=buf(32,seed+67);privateKey[0]&=248;privateKey[31]=(privateKey[31]&127)|64;peerPrivate[0]&=248;peerPrivate[31]=(peerPrivate[31]&127)|64;
  const publicKey=curve.getPublicFromPrivateKey(privateKey),peerPublic=curve.getPublicFromPrivateKey(peerPrivate);
  agreements.push({privateKey:arr(privateKey),publicKey:arr(publicKey),peerPublic:arr(peerPublic),shared:arr(c.Curve.sharedKey(privateKey,peerPublic))});
 }
 const salt=buf(32,19),code='ABCD-1234';const pairing={salt:arr(salt),code,key:arr(await c.derivePairingCodeKey(code,salt))};
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/crypto-upstream.json'),JSON.stringify({upstream_commit:expected,bridge_version:'0.5.4',libsignal_version:'6.0.0',synthetic_data:true,cases,derivations,agreements,pairing})+'\n');
 console.log(`${cases.length} symmetric/hash vectors, ${derivations.length} HKDF vectors, ${agreements.length} X25519 agreements, 1 pairing derivation`);
})().catch(e=>{console.error(e);process.exit(1)});
