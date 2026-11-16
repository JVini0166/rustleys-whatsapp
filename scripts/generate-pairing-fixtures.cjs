const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {reference,nodeToJson}=require('./pairing-reference.cjs');
(async()=>{
 const r=await reference(process.argv[2]),creds=r.credentials[0],payloads=[],pairings=[],negative=[];
 const browsers=[['Mac OS','Chrome','14.4.1'],['Windows','Desktop','10'],['Mac OS','Desktop','14'],['Ubuntu','Desktop','22'],['Android','Android',''],['Ubuntu','FIREFOX','1'],['Ubuntu','Firefox','1'],['Other','Unknown','1'],['Other','UNKNOWN','1'],['Ubuntu','Edge','1']];
 for(const browser of browsers)for(const syncFullHistory of [false,true]){
  const config={version:[2,3000,1043857760],browser,countryCode:syncFullHistory?'BR':'US',syncFullHistory,pushName:syncFullHistory?'Synthetic Tester':null};
  const registration=r.generateRegistrationNode(creds,config);const logins=['15550001111@s.whatsapp.net','15550001111:0@s.whatsapp.net','15550001111:5@s.whatsapp.net','123:99@hosted','9007199254740991:2@lid'];
  payloads.push({config,registration:Array.from(r.proto.ClientPayload.encode(registration).finish()),logins:logins.map(jid=>({jid,bytes:Array.from(r.proto.ClientPayload.encode(r.generateLoginNode(jid,config)).finish())})),qr:r.buildPairingQRData('synthetic-ref',Buffer.from(creds.noiseKey.public).toString('base64'),Buffer.from(creds.signedIdentityKey.public).toString('base64'),creds.advSecretKey,browser),companion:r.getCompanionPlatformId(browser)});
 }
 const accountKey=r.crypto.Curve.generateKeyPair();
 for(const accountType of [0,1])for(const deviceType of [0,1]){
  const deviceDetails=r.proto.ADVDeviceIdentity.encode({rawId:42,timestamp:1700000000,keyIndex:7,accountType,deviceType}).finish();
  const prefix=deviceType===1?r.prefixes.WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX:r.prefixes.WA_ADV_ACCOUNT_SIG_PREFIX;
  const signature=r.crypto.Curve.sign(accountKey.private,Buffer.concat([prefix,deviceDetails,creds.signedIdentityKey.public]));
  const makeStanza=(badHmac=false,badSignature=false)=>{
   const sig=Buffer.from(signature);if(badSignature)sig[0]^=1;
   const account=r.proto.ADVSignedDeviceIdentity.encode({details:deviceDetails,accountSignatureKey:accountKey.public,accountSignature:sig}).finish();
   const hmac=r.crypto.hmacSign(Buffer.concat([accountType===1?r.prefixes.WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX:Buffer.alloc(0),account]),Buffer.from(creds.advSecretKey,'base64'));if(badHmac)hmac[0]^=1;
   return {tag:'iq',attrs:{id:'synthetic-pair',type:'set'},content:[{tag:'pair-success',attrs:{},content:[{tag:'device-identity',attrs:{},content:r.proto.ADVSignedDeviceIdentityHMAC.encode({details:account,hmac,accountType}).finish()},{tag:'device',attrs:{jid:'15550001111:5@s.whatsapp.net',lid:'100000000000000001:5@lid'}},{tag:'platform',attrs:{name:'android'}},...(deviceType?[{tag:'biz',attrs:{name:'Synthetic Business'}}]:[])]}]};
  };
  const stanza=makeStanza(),configured=r.configureSuccessfulPairing(stanza,creds);
  pairings.push({accountType,deviceType,stanza:nodeToJson(stanza),me:configured.creds.me,platform:configured.creds.platform,identities:JSON.parse(JSON.stringify(configured.creds.signalIdentities,r.BufferJSON.replacer)),account:JSON.parse(JSON.stringify(configured.creds.account,r.BufferJSON.replacer)),reply:nodeToJson(configured.reply)});
  const invalidHmac=makeStanza(true);assert.throws(()=>r.configureSuccessfulPairing(invalidHmac,creds));negative.push({name:'bad_hmac',stanza:nodeToJson(invalidHmac),expected:'InvalidHmac',originalAccepted:false});
  const invalidSignature=makeStanza(false,true);let accepted=true;try{r.configureSuccessfulPairing(invalidSignature,creds);}catch{accepted=false;}
  negative.push({name:'bad_account_signature',stanza:nodeToJson(invalidSignature),expected:'InvalidAccountSignature',originalAccepted:accepted});
 }
 fs.writeFileSync(path.join(__dirname,'../tests/fixtures/pairing-upstream.json'),JSON.stringify({upstream_commit:r.commit,synthetic_data:true,credentials:r.credentialJson[0],payloads,pairings,negative},null,2)+'\n');
 console.log(`${payloads.length} registration/QR cases, ${payloads.length*5} login payloads, ${pairings.length} signed pairings and ${negative.length} rejection cases; original bad-signature acceptance: ${negative.filter(n=>n.name==='bad_account_signature'&&n.originalAccepted).length}`);
})().catch(e=>{console.error(e.message);process.exitCode=1;});
