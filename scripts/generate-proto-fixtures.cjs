// Run the pinned generated protobuf.js bindings as the wire oracle.
const fs=require('node:fs'),path=require('node:path'),{execFileSync}=require('node:child_process'),pb=require('protobufjs');
const upstream=process.argv[2],expected=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/upstream-inventory.json'))).commit;
if(!upstream||execFileSync('git',['-C',upstream,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==expected)throw Error('Expected pinned upstream');
const source=execFileSync('git',['-C',upstream,'show',`${expected}:WAProto/index.js`],{encoding:'utf8',maxBuffer:16*1024*1024});
const code=source.replace('import $protobuf from "protobufjs/minimal.js";','const $protobuf = require("protobufjs/minimal.js");').replace('export const proto =','const proto = module.exports.proto =').replace('export { $root as default };','');
const m={exports:{}};new Function('require','module','exports',code)(require,m,m.exports);
const schema=execFileSync('git',['-C',upstream,'show',`${expected}:WAProto/WAProto.proto`],{encoding:'utf8'});
const root=pb.parse(schema).root;root.resolveAll();const options={bytes:String,longs:String,enums:String};
function sample(f,depth=0,allowConflicts=false){
 if(f.resolvedType instanceof pb.Enum){const values=Object.values(f.resolvedType.values);return values.find(v=>v!==0)??values[0];}
 if(f.resolvedType instanceof pb.Type){if(depth>=2)return {};const result={},seen=new Set();for(const child of f.resolvedType.fieldsArray.slice(0,2)){if(!allowConflicts&&child.partOf&&seen.has(child.partOf.name))continue;if(child.partOf)seen.add(child.partOf.name);result[child.name]=field(child,depth+1,allowConflicts);}return result;}
 if(f.type==='string')return 'synthetic ✓';if(f.type==='bytes')return Buffer.from([0,1,255,128]).toString('base64');if(f.type==='bool')return true;
 if(f.type.includes('64'))return f.type.startsWith('u')||f.type==='fixed64'?'18446744073709551615':'-9007199254740993';
 if(f.type==='float'||f.type==='double')return 1.25;return f.type==='uint32'||f.type==='fixed32'?4000000000:-123;
}
function field(f,depth,allowConflicts=false){const v=sample(f,depth,allowConflicts);return f.map?{[f.keyType==='string'?'example':f.keyType==='bool'?'true':'7']:v}:f.repeated?[v]:v;}
const cases=[],legacy_invalid_oneofs=[],types=[],enums=[],message_fields=[];function walk(namespace){for(const child of Object.values(namespace.nested||{})){
 if(child instanceof pb.Type){const name=child.fullName.slice(1),ctor=name.split('.').reduce((v,k)=>v[k],m.exports);types.push(name);message_fields.push({name,fields:child.fieldsArray.map(f=>({name:f.name,number:f.id,type:f.resolvedType?f.resolvedType.fullName.slice(1):f.type,list:!!f.repeated,map:!!f.map,key_type:f.keyType??null}))});
  for(const f of child.fieldsArray){const input=ctor.fromObject({[f.name]:field(f,0)}),wire=ctor.encode(input).finish();const row={type:name,field:f.name,input:ctor.toObject(input,options),schema_input:{[f.name]:field(f,0)},wire:[...wire]};cases.push(row);
   const legacy=ctor.fromObject({[f.name]:field(f,0,true)});const legacyJson=ctor.toObject(legacy,options);
   if(JSON.stringify(legacyJson)!==JSON.stringify(row.input))legacy_invalid_oneofs.push({type:name,field:f.name,input:legacyJson,wire:[...ctor.encode(legacy).finish()]});}
 }if(child instanceof pb.Enum)enums.push({name:child.fullName.slice(1),values:child.values});walk(child);
}}walk(root);
fs.writeFileSync(path.join(__dirname,'../tests/fixtures/proto-upstream.json'),JSON.stringify({upstream_commit:expected,schema_sha256:require('node:crypto').createHash('sha256').update(schema).digest('hex'),message_types:types,message_fields,enum_types:enums,cases,legacy_invalid_oneofs})+'\n');
console.log(`${types.length} message types inventoried; ${cases.length} per-field wire vectors; ${legacy_invalid_oneofs.length} legacy oneof-conflict vectors`);
