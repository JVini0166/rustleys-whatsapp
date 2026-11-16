// Rust-encoded frames are independently decoded by the pinned original JS code.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{execFileSync,spawnSync}=require('node:child_process');
const root=path.join(__dirname,'..'),fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/proto-upstream.json'))),upstream=process.argv[2];
if(!upstream||execFileSync('git',['-C',upstream,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==fixture.upstream_commit)throw Error('Expected pinned upstream');
const source=execFileSync('git',['-C',upstream,'show',`${fixture.upstream_commit}:WAProto/index.js`],{encoding:'utf8',maxBuffer:16*1024*1024});
const code=source.replace('import $protobuf from "protobufjs/minimal.js";','const $protobuf = require("protobufjs/minimal.js");').replace('export const proto =','const proto = module.exports.proto =').replace('export { $root as default };','');
const m={exports:{}};new Function('require','module','exports',code)(require,m,m.exports);
const result=spawnSync('cargo',['run','--locked','--quiet','--example','protobuf_crosscheck'],{cwd:root,env:{...process.env,CARGO_BUILD_JOBS:'1'},encoding:'utf8',input:JSON.stringify(fixture.cases),maxBuffer:16*1024*1024});
if(result.status!==0){process.stderr.write(result.stderr||'Rust encoder failed');process.exit(1);}
const rows=result.stdout.trim().split('\n').map(s=>JSON.parse(s));assert.equal(rows.length,fixture.cases.length);
let wireDifferences=0;const options={defaults:true,arrays:true,objects:true,bytes:String,longs:String,enums:String};
for(let i=0;i<rows.length;i++){
 const row=fixture.cases[i],type=row.type.split('.').reduce((v,k)=>v[k],m.exports);
 const original=type.toObject(type.decode(Buffer.from(row.wire)),options),rust=type.toObject(type.decode(Buffer.from(rows[i])),options);
 assert.deepEqual(rust,original,`${row.type}.${row.field} vector ${i}`);
 if(!Buffer.from(rows[i]).equals(Buffer.from(row.wire)))wireDifferences++;
}
console.log(`${rows.length} Rust frames decoded with equivalent values by the original JS bindings; ${wireDifferences} valid canonical/default-field encoding differences`);
