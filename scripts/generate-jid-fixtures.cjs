// Execute the pinned upstream implementation, not a reimplementation of it.
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const ts = require(process.env.TYPESCRIPT_PATH || 'typescript');
const upstream = process.argv[2];
if (!upstream) throw Error('Pass the path to a checkout of the pinned Baileys commit');
const expected = JSON.parse(fs.readFileSync(path.join(__dirname, '../docs/upstream-inventory.json'))).commit;
if (execFileSync('git',['-C',upstream,'rev-parse','HEAD'],{encoding:'utf8'}).trim() !== expected) throw Error('Wrong upstream commit');
const source = execFileSync('git',['-C',upstream,'show',`${expected}:src/WABinary/jid-utils.ts`],{encoding:'utf8'});
const js = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
const m={exports:{}};new Function('module','exports',js)(m,m.exports);const api=m.exports;
const predicates=['isJidMetaAI','isPnUser','isLidUser','isJidBroadcast','isJidGroup','isJidStatusBroadcast','isJidNewsletter','isHostedPnUser','isHostedLidUser','isJidBot'];
const servers=['c.us','g.us','broadcast','s.whatsapp.net','call','lid','newsletter','bot','hosted','hosted.lid'];
const values=['','0','123','status','13135550002','13165550001','群組','alice'];
const rows=[];
for(const server of servers)for(const user of values)for(const device of [undefined,0,1,255,65535])for(const agent of [undefined,0,1,128,129]) {
 const encoded=api.jidEncode(user,server,device,agent);
 rows.push({user,server,device:device??null,agent:agent??null,encoded,decoded:api.jidDecode(encoded),normalized:api.jidNormalizedUser(encoded),predicates:predicates.map(p=>Boolean(api[p](encoded))),transferred:api.transferDevice(encoded,'target@lid')});
}
const result={upstream_commit:expected,scope:'unsigned protocol-integer JIDs; malformed JavaScript numeric coercions not covered',cases:rows};
fs.writeFileSync(path.join(__dirname,'../tests/fixtures/jid-upstream.json'),JSON.stringify(result)+'\n');
console.log(`${rows.length} cases from the pinned upstream implementation`);
