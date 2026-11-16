const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process'),curve=require('libsignal/src/curve');
const root=path.join(__dirname,'..'),fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/crypto-upstream.json')));
const result=spawnSync('cargo',['run','--locked','--quiet','--example','signature_crosscheck'],{cwd:root,env:{...process.env,CARGO_BUILD_JOBS:'1'},encoding:'utf8',maxBuffer:8*1024*1024});
if(result.status!==0){process.stderr.write(result.stderr||'Rust signature example failed');process.exit(1);}
const signatures=result.stdout.trim().split('\n').map(s=>JSON.parse(s));assert.equal(signatures.length,fixture.agreements.length);
for(let i=0;i<signatures.length;i++){
 const vector=fixture.agreements[i],actual=signatures[i],pub=Buffer.from(vector.publicKey),message=Buffer.from(vector.message);
 assert(curve.verifySignature(pub,message,Buffer.from(actual.signature)),`Rust XEdDSA ${i}`);
 assert(curve.verifySignature(pub,Buffer.concat([Buffer.from([5]),Buffer.from(actual.prekeyPublic)]),Buffer.from(actual.prekeySignature)),`Rust signed prekey ${i}`);
}
console.log(`${signatures.length} Rust XEdDSA signatures and signed prekeys verified by original libsignal-node`);
