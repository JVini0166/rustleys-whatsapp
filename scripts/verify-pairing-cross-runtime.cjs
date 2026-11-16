const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),curve=require('libsignal/src/curve');
const {reference,nodeFromJson}=require('./pairing-reference.cjs');const {buildDriver,startDriver}=require('./rust-oracle-driver.cjs');
(async()=>{
 const r=await reference(process.argv[2]),root=path.join(__dirname,'..'),fixture=JSON.parse(fs.readFileSync(path.join(root,'tests/fixtures/pairing-upstream.json'))),credentials=JSON.parse(fixture.credentials),driver=startDriver(buildDriver(root,'pairing_crosscheck'),[],root);let comparisons=0;
 try{
 for(const row of fixture.payloads){
  const registration=Buffer.from(await driver.request({command:'registration',credentials,config:row.config}));assert.deepEqual(registration,Buffer.from(row.registration));assert.deepEqual(r.proto.ClientPayload.decode(registration).toJSON(),r.proto.ClientPayload.fromObject(r.generateRegistrationNode(r.credentials[0],row.config)).toJSON());comparisons++;
  for(const login of row.logins){const encoded=Buffer.from(await driver.request({command:'login',credentials,config:row.config,jid:login.jid}));assert.deepEqual(encoded,Buffer.from(login.bytes));assert.deepEqual(r.proto.ClientPayload.decode(encoded).toJSON(),r.generateLoginNode(login.jid,row.config).toJSON());comparisons++;}
  assert.equal(await driver.request({command:'qr',credentials,browser:row.config.browser,reference:'synthetic-ref'}),row.qr);comparisons++;
 }
 for(const row of fixture.pairings){
  const output=await driver.request({command:'pair',credentials,stanza:row.stanza}),reply=nodeFromJson(output.reply),native=r.proto.ADVSignedDeviceIdentity.fromObject(output.credentials.account);
  assert.deepEqual(output.credentials.me,row.me);assert.deepEqual(output.credentials.signalIdentities,row.identities);
  for(const key of ['details','accountSignatureKey','accountSignature'])assert.equal(output.credentials.account[key],row.account[key]);
  const message=Buffer.concat([r.prefixes.WA_ADV_DEVICE_SIG_PREFIX,native.details,r.credentials[0].signedIdentityKey.public,native.accountSignatureKey]);
  // Check the raw boolean result. The original Curve.verify wrapper ignores it.
  assert.equal(curve.verifySignature(r.crypto.generateSignalPubKey(r.credentials[0].signedIdentityKey.public),message,native.deviceSignature),true);
  const corrupted=Buffer.from(native.deviceSignature);corrupted[0]^=1;assert.equal(curve.verifySignature(r.crypto.generateSignalPubKey(r.credentials[0].signedIdentityKey.public),message,corrupted),false);
  const signed=r.proto.ADVSignedDeviceIdentity.decode(reply.content[0].content[0].content);assert.equal(Object.hasOwn(signed,'accountSignatureKey'),false);assert.deepEqual(signed.deviceSignature,native.deviceSignature);assert.equal(reply.content[0].content[0].attrs['key-index'],'7');assert.equal(reply.attrs.id,row.stanza.attrs.id);comparisons++;
 }
 for(const row of fixture.negative){await assert.rejects(driver.request({command:'pair',credentials,stanza:row.stanza}),new RegExp(row.expected));comparisons++;}
 console.log(`${comparisons} independent pairing comparisons passed: 20 registration payloads, 100 logins, 20 QR strings, 4 Rust-signed replies verified by Node and 8 rejection cases`);
 }finally{await driver.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
