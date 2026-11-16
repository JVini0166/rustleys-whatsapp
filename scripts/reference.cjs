// Development-only loader for the exact, public, pinned reference sources.
const fs=require('node:fs'),path=require('node:path'),{execFileSync}=require('node:child_process'),ts=require('typescript');
async function loadReference(upstream,rootOverride){
 const expected=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/upstream-inventory.json'))).commit;
 if(!upstream||execFileSync('git',['-C',upstream,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==expected)throw Error('Expected pinned upstream');
 const source=file=>execFileSync('git',['-C',upstream,'show',`${expected}:${file}`],{encoding:'utf8',maxBuffer:16*1024*1024});
 const compile=(src,req)=>{const code=ts.transpileModule(src,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;const m={exports:{}};new Function('require','module','exports',code)(req,m,m.exports);return m.exports;};
 const defaultsTree=ts.createSourceFile('defaults.ts',source('src/Defaults/index.ts'),ts.ScriptTarget.Latest,true);
 const names=new Set(['NOISE_MODE','DICT_VERSION','KEY_BUNDLE_TYPE','NOISE_WA_HEADER','WA_CERT_DETAILS']);
 const constants=compile(defaultsTree.statements.filter(s=>ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>names.has(d.name.getText(defaultsTree)))).map(s=>s.getText(defaultsTree)).join('\n'),require);
 if(rootOverride)constants.WA_CERT_DETAILS={...constants.WA_CERT_DETAILS,PUBLIC_KEY:Buffer.from(rootOverride)};
 const bridge=await import('whatsapp-rust-bridge');
 const crypto=compile(source('src/Utils/crypto.ts'),n=>n==='../Defaults'?constants:n==='whatsapp-rust-bridge'?bridge:require(n));
 const cache={};function binaryLoad(name){return cache[name]??(cache[name]=compile(source(`src/WABinary/${name}.ts`),n=>n.startsWith('./')?binaryLoad(n.slice(2)):require(n)));}
 const binary={...binaryLoad('encode'),...binaryLoad('decode')};
 const protoSource=source('WAProto/index.js').replace('import $protobuf from "protobufjs/minimal.js";','const $protobuf = require("protobufjs/minimal.js");').replace('export const proto =','const proto = module.exports.proto =').replace('export { $root as default };','');
 const m={exports:{}};new Function('require','module','exports',protoSource)(require,m,m.exports);const proto=m.exports.proto;
 const noise=compile(source('src/Utils/noise-handler.ts'),n=>n==='../Defaults'?constants:n==='./crypto'?crypto:n==='../WABinary'?binary:n==='../../WAProto/index.js'?{proto}:require(n));
 return {commit:expected,crypto,binary,proto,constants,noise};
}
module.exports={loadReference};
