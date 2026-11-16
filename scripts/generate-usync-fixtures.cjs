const fs=require('node:fs'),path=require('node:path');const {reference,normalize}=require('./usync-reference.cjs');const {nodeToJson}=require('./pairing-reference.cjs');
const n=(tag,attrs={},content)=>({tag,attrs,content}),text=(tag,s)=>n(tag,{},s);
(async()=>{const r=await reference(process.argv[2]),builds=[],parsers=[],results=[];
 const users=[{id:'123@s.whatsapp.net'},{phone:'+5511999999999'},{id:'ignored@s.whatsapp.net',phone:'+123',username:'ignored'},{id:'123@s.whatsapp.net',lid:'999@lid',username:'alice',usernameKey:'1234',type:'ignored'},{type:'business'},{username:'',phone:'',id:'456@s.whatsapp.net',lid:''},{personaId:'test-persona',id:'1@bot'},{}, {id:'',phone:'',username:'bob',usernameKey:'',lid:'999@lid'}];
 const names=Object.keys(r.classes);for(const protocols of [...names.map(p=>[p]),names,['contact','contact','lid'],['devices','lid'],['contact','username'],[]]){
  const config={protocols,users,mode:'query',context:'interactive'},sid='synthetic-usync.17';let captured;
  try{await r.methods(async node=>{captured=node;return undefined;},sid).executeUSyncQuery(r.make(config));builds.push({config,sid,node:nodeToJson(captured),wire:Array.from(r.binary.encodeBinaryNode(captured))});}catch{builds.push({config,sid,error:true});}
 }
 function parse(protocol,input){const p=new r.classes[protocol]();try{parsers.push({protocol,node:nodeToJson(input),expected:normalize(p.parser(input))??null});}catch{parsers.push({protocol,node:nodeToJson(input),error:true});}}
 const numbers=[undefined,'','0','1','-0','-1','1.5','1e3','0x10','0b11','0o17','  12  ','\ufeff5\u00a0','\u0085','NaN','Infinity','-Infinity','9007199254740992','8640000000000','8640000000001','not-number','0xd87a1cbe50f29436d87a1cbe50f29436d87a1cbe50f29436d87a1cbe50f29436d87a1cbe50f29436d87a1cbe5'];
 for(const t of numbers){parse('devices',n('devices',{},[n('device-list',{},[n('ignored',{id:'broken'}),n('device',{id:t,'key-index':t,is_hosted:'true'}),n('device',{id:'0','key-index':'0',is_hosted:'false'})]),n('key-index-list',{ts:t,expected_ts:t},Buffer.from([0,255,1]))]));parse('disappearing_mode',n('disappearing_mode',{duration:t,t}));parse('status',n('status',{t},Buffer.from('Olá 👋')));}
 for(const content of [undefined,'',Buffer.alloc(0),'hello',Buffer.from([0xff,0xc3,0x28]),Buffer.from('مرحبا')])for(const code of [undefined,'401','404'])parse('status',n('status',{code},content));
 for(const type of [undefined,'in','out','', 'IN'])parse('contact',n('contact',{type}));
 for(const value of [undefined,'','999@lid'])parse('lid',n('lid',{val:value}));
 for(const content of [undefined,'','alice',Buffer.from('alice')])parse('username',n('username',{},content));
 for(const name of names){parse(name,n('other'));if(!['bot','lid'].includes(name))parse(name,n(name,{},[n('error',{code:'403',text:'fixture error'})]));}
 const profile=n('profile',{persona_id:'persona'},[n('default'),text('name','Assistant'),text('attributes',Buffer.from('friendly')),text('description','description'),text('category','help'),n('commands',{},[text('description','commands'),n('command',{},[text('name','hello'),text('description','greet')]),n('command')]),n('prompts',{},[n('prompt',{},[text('emoji','👋'),text('text','Hello')]),n('prompt')])]);
 parse('bot',n('user',{jid:'123@bot'},[n('bot',{},[profile])]));parse('bot',n('bot',{jid:'123@bot'},[n('bot',{},[profile])]));parse('bot',n('bot',{},[profile]));
 function result(config,node){try{results.push({config,node:nodeToJson(node),expected:normalize(r.make(config).parseUSyncQueryResult(node))??null});}catch{results.push({config,node:nodeToJson(node),error:true});}}
 const config={protocols:names,users:[]};result(config,n('iq',{type:'result'},[n('usync',{},[n('list',{},[n('user',{jid:'123@s.whatsapp.net'},[n('contact',{type:'in'}),n('lid',{val:'999@lid'}),n('username',{},'alice'),n('status',{t:'1'},Buffer.from('Hello')),n('unknown',{},'ignored')]),n('user',{jid:''}),n('other',{jid:'456@s.whatsapp.net'},[n('contact',{type:'out'}),n('contact',{type:'in'}),n('username',{},'first'),n('username',{},Buffer.from('omitted'))])]),n('side_list',{},[n('user',{jid:'ignored@s.whatsapp.net'})])])]));
 result(config,n('iq',{type:'error'}));result(config,n('iq',{type:'result'}));result(config,n('iq',{type:'result'},[n('usync',{},[n('list',{},[n('user',{jid:'1@bot'},[n('bot',{},[profile])])])])]));result({protocols:['bot'],users:[]},n('iq',{type:'result'},[n('usync',{},[n('list',{},[n('user',{jid:'1@bot'},[n('bot',{jid:'2@bot'},[n('bot',{},[profile])])])])])]));
 const differences=[];
 for(const tag of ['toString','constructor','__proto__']){
  const config={protocols:['contact'],users:[]},input=n('iq',{type:'result'},[n('usync',{},[n('list',{},[n('user',{jid:'synthetic@s.whatsapp.net'},[n(tag)])])])]);
  const row={reason:'Ignore inherited Object.prototype names unless explicitly registered',config,node:nodeToJson(input),native:{list:[{id:'synthetic@s.whatsapp.net'}],sideList:[]}};
  try{row.original=normalize(r.make(config).parseUSyncQueryResult(input));}catch{row.original_error=true;}differences.push(row);
 }
 const output={upstream_commit:r.commit,builds,parsers,results,differences};fs.writeFileSync(path.join(__dirname,'../tests/fixtures/usync-upstream.json'),JSON.stringify(output,null,2)+'\n');console.log(`${builds.length} query builders, ${parsers.length} protocol parser cases, ${results.length} aggregate results generated from pinned original classes/methods`);
})().catch(e=>{console.error(e.stack);process.exitCode=1});
