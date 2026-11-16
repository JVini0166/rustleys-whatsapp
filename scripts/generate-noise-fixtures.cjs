const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),curve=require('libsignal/src/curve'),{loadReference}=require('./reference.cjs');
const bytes=b=>[...b],buf=a=>Buffer.from(a);
function key(seed){const private=Buffer.from(Array.from({length:32},(_,i)=>(seed+37*i)&255));private[0]&=248;private[31]=(private[31]&127)|64;const public=curve.getPublicFromPrivateKey(private).subarray(1);return {private,public};}
const norm=n=>({tag:n.tag,attrs:n.attrs,content:Buffer.isBuffer(n.content)?{bytes:[...n.content]}:Array.isArray(n.content)?n.content.map(norm):n.content??null});
const logger={level:'silent',child(){return this},trace(){}};
function frame(b){return Buffer.concat([Buffer.from([b.length>>16,(b.length>>8)&255,b.length&255]),b]);}
(async()=>{
 const root=key(201),r=await loadReference(process.argv[2],root.public),{crypto:c,binary,proto,constants,noise}=r;
 const cases=[],negative=[];
 for(const [index,routing]of [undefined,Buffer.alloc(0),Buffer.from([1,2,3,255])].entries()){
  const client=key(1+index),clientStatic=key(21+index),serverEph=key(61+index),serverStatic=key(91+index),intermediate=key(131+index);
  const details=proto.CertChain.NoiseCertificate.Details;
  const intBytes=proto.CertChain.NoiseCertificate.Details.encode(details.fromObject({serial:7,issuerSerial:0,key:intermediate.public})).finish();
  const leafBytes=details.encode(details.fromObject({serial:8,issuerSerial:7,key:serverStatic.public})).finish();
  const intSignature=c.Curve.sign(root.private,intBytes),leafSignature=c.Curve.sign(intermediate.private,leafBytes);
  const cert=proto.CertChain.encode({intermediate:{details:intBytes,signature:intSignature},leaf:{details:leafBytes,signature:leafSignature}}).finish();
  const newClient=()=>noise.makeNoiseHandler({keyPair:client,NOISE_HEADER:constants.NOISE_WA_HEADER,logger,routingInfo:routing});
  const prepareServer=certificate=>{
   const server=newClient();let salt=Buffer.from(constants.NOISE_MODE);
   const mix=data=>{server.mixIntoKey(data);salt=buf(c.hkdf(data,64,{salt,info:''})).subarray(0,32);};
   server.authenticate(serverEph.public);mix(c.Curve.sharedKey(serverEph.private,client.public));
   const encryptedStatic=server.encrypt(serverStatic.public);mix(c.Curve.sharedKey(serverStatic.private,client.public));
   const payload=server.encrypt(certificate);return {server,mix,get salt(){return salt},hello:{ephemeral:serverEph.public,static:encryptedStatic,payload}};
  };
  const server=prepareServer(cert),handler=newClient();
  const clientHello=proto.HandshakeMessage.encode({clientHello:{ephemeral:client.public}}).finish();const clientHelloFrame=handler.encodeFrame(clientHello);
  const serverHello=proto.HandshakeMessage.encode({serverHello:server.hello}).finish();
  const keyEncrypted=handler.processHandshake({serverHello:server.hello},clientStatic);
  assert.deepEqual(buf(server.server.decrypt(keyEncrypted)),clientStatic.public);
  server.mix(c.Curve.sharedKey(serverEph.private,clientStatic.public));
  const clientPayload=Buffer.from(`synthetic-login-${index}`),payloadEncrypted=handler.encrypt(clientPayload);assert.deepEqual(buf(server.server.decrypt(payloadEncrypted)),clientPayload);
  const clientFinish=proto.HandshakeMessage.encode({clientFinish:{static:keyEncrypted,payload:payloadEncrypted}}).finish(),clientFinishFrame=handler.encodeFrame(clientFinish);
  const split=buf(c.hkdf(Buffer.alloc(0),64,{salt:server.salt,info:''}));await handler.finishInit();
  const outgoing=[],incoming=[];
  for(let counter=0;counter<3;counter++){
   const node={tag:'iq',attrs:{id:`synthetic-${counter}`,type:'get'},content:[{tag:'ping',attrs:{xmlns:'w:p'}}]},plain=binary.encodeBinaryNode(node);
   outgoing.push({plaintext:bytes(plain),frame:bytes(handler.encodeFrame(plain))});
   const ack={tag:'ack',attrs:{id:`synthetic-${counter}`,class:'message'}},raw=binary.encodeBinaryNode(ack),nonce=Buffer.alloc(12);nonce.writeUInt32BE(counter,8);
   const wire=frame(c.aesEncryptGCM(raw,split.subarray(32),nonce,Buffer.alloc(0)));const read=[];
   // Also exercise the original fragment buffering before committing expected output.
   for(let offset=0;offset<wire.length;offset+=5)await handler.decodeFrame(wire.subarray(offset,offset+5),n=>read.push(norm(n)));
   assert.equal(read.length,1);incoming.push({frame:bytes(wire),node:read[0]});
  }
  cases.push({synthetic:true,clientPrivate:bytes(client.private),clientStaticPrivate:bytes(clientStatic.private),serverStaticPublic:bytes(serverStatic.public),routing:routing?bytes(routing):null,rootPublic:bytes(root.public),certificate:bytes(cert),serverHello:bytes(serverHello),serverHelloFrame:bytes(frame(serverHello)),clientHelloFrame:bytes(clientHelloFrame),keyEncrypted:bytes(keyEncrypted),clientPayload:bytes(clientPayload),payloadEncrypted:bytes(payloadEncrypted),clientFinishFrame:bytes(clientFinishFrame),outgoing,incoming});
  if(index===0){
   const variants=[];
   const change=overrides=>proto.CertChain.encode({intermediate:{details:intBytes,signature:intSignature},leaf:{details:leafBytes,signature:leafSignature},...overrides}).finish();
   const badInt=Buffer.from(intSignature);badInt[0]^=128;variants.push(['intermediate_signature',change({intermediate:{details:intBytes,signature:badInt}}),'InvalidCertificate']);
   const badLeaf=Buffer.from(leafSignature);badLeaf[0]^=128;variants.push(['leaf_signature',change({leaf:{details:leafBytes,signature:badLeaf}}),'InvalidCertificate']);
   const mismatch=details.encode(details.fromObject({serial:8,issuerSerial:7,key:key(229).public})).finish();variants.push(['static_binding',change({leaf:{details:mismatch,signature:c.Curve.sign(intermediate.private,mismatch)}}),'StaticKeyMismatch']);
   const issuer=details.encode(details.fromObject({serial:7,issuerSerial:9,key:intermediate.public})).finish();variants.push(['root_issuer',change({intermediate:{details:issuer,signature:c.Curve.sign(root.private,issuer)}}),'InvalidIssuer']);
   const leafIssuer=details.encode(details.fromObject({serial:8,issuerSerial:99,key:serverStatic.public})).finish();variants.push(['leaf_issuer',change({leaf:{details:leafIssuer,signature:c.Curve.sign(intermediate.private,leafIssuer)}}),'InvalidIssuer']);
   variants.push(['missing_leaf',proto.CertChain.encode({intermediate:{details:intBytes,signature:intSignature}}).finish(),'MissingCertificate']);
   variants.push(['missing_intermediate',proto.CertChain.encode({leaf:{details:leafBytes,signature:leafSignature}}).finish(),'MissingCertificate']);
   variants.push(['malformed_proto',Buffer.from([255]),'InvalidProtobuf']);
   for(const [name,badCert,expectedError]of variants){const serverBad=prepareServer(badCert),reference=newClient();let referenceAccepted=true;try{reference.processHandshake({serverHello:serverBad.hello},clientStatic)}catch{referenceAccepted=false;}
    negative.push({name,certificate:bytes(badCert),serverHello:bytes(proto.HandshakeMessage.encode({serverHello:serverBad.hello}).finish()),expectedError,referenceAccepted});}
  }
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/noise-upstream.json'),JSON.stringify({upstream_commit:r.commit,synthetic_data:true,realWaRootPublic:bytes((await loadReference(process.argv[2])).constants.WA_CERT_DETAILS.PUBLIC_KEY),header:bytes(constants.NOISE_WA_HEADER),cases,negative})+'\n');
 console.log(`${cases.length} complete synthetic reference handshakes, 9 frames in each direction, ${negative.length} certificate rejection cases`);
})().catch(e=>{console.error(e);process.exit(1)});
