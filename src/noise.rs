//! Baileys Noise_XX framing/transcript and authenticated transport.
//! Never permits transition to transport before server certificate verification.
use crate::{binary, crypto, proto};
use bytes::{Bytes, BytesMut};
use prost::Message;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const NOISE_MODE: &[u8] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";
pub const NOISE_WA_HEADER: [u8; 4] = [87, 65, 6, 3];
pub const MAX_FRAME_SIZE: usize = 0xff_ffff;
const WA_ROOT: [u8; 32] = [
    20, 35, 117, 87, 77, 10, 88, 113, 102, 170, 231, 30, 190, 81, 100, 55, 196, 162, 139, 115, 227,
    105, 92, 108, 225, 247, 249, 84, 93, 168, 238, 107,
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Crypto(crypto::Error),
    Binary(binary::Error),
    InvalidProtobuf,
    MissingCertificate,
    InvalidCertificate,
    InvalidIssuer,
    StaticKeyMismatch,
    InvalidHandshake,
    HandshakeOrder,
    CounterExhausted,
    FrameTooLarge,
    BufferLimit,
    InvalidLimit,
    Failed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}
impl From<binary::Error> for Error {
    fn from(e: binary::Error) -> Self {
        Self::Binary(e)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn nonce(counter: &mut u64) -> Result<[u8; 12]> {
    let c = u32::try_from(*counter).map_err(|_| Error::CounterExhausted)?;
    *counter += 1;
    let mut iv = [0; 12];
    iv[8..].copy_from_slice(&c.to_be_bytes());
    Ok(iv)
}
fn split_keys(input: &[u8], salt: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let material = Zeroizing::new(crypto::hkdf(input, 64, Some(salt), b"")?);
    let mut first = [0; 32];
    let mut second = [0; 32];
    first.copy_from_slice(&material[..32]);
    second.copy_from_slice(&material[32..]);
    Ok((first, second))
}
#[derive(Zeroize, ZeroizeOnDrop)]
struct Transcript {
    hash: [u8; 32],
    salt: [u8; 32],
    key: [u8; 32],
    counter: u64,
}
impl Transcript {
    fn new(header: &[u8], public: &[u8]) -> Self {
        let hash = NOISE_MODE
            .try_into()
            .unwrap_or_else(|_| crypto::sha256(NOISE_MODE));
        let mut s = Self {
            hash,
            salt: hash,
            key: hash,
            counter: 0,
        };
        s.authenticate(header);
        s.authenticate(public);
        s
    }
    fn authenticate(&mut self, data: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(self.hash);
        hash.update(data);
        self.hash = hash.finalize().into();
    }
    fn mix_key(&mut self, data: &[u8]) -> Result<()> {
        let (salt, key) = split_keys(data, &self.salt)?;
        self.salt = salt;
        self.key = key;
        self.counter = 0;
        Ok(())
    }
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let iv = nonce(&mut self.counter)?;
        let out = crypto::aes_encrypt_gcm(data, &self.key, &iv, &self.hash)?;
        self.authenticate(&out);
        Ok(out)
    }
    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let iv = nonce(&mut self.counter)?;
        let out = crypto::aes_decrypt_gcm(data, &self.key, &iv, &self.hash)?;
        self.authenticate(data);
        Ok(out)
    }
    fn finish(&self) -> Result<TransportCipher> {
        let (write, read) = split_keys(b"", &self.salt)?;
        Ok(TransportCipher::new(write, read))
    }
}
/// Low-level paired transport keys. No Clone: cloning a counter state can reuse nonces.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransportCipher {
    write_key: [u8; 32],
    read_key: [u8; 32],
    write_counter: u64,
    read_counter: u64,
    failed: bool,
}
impl std::fmt::Debug for TransportCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportCipher([redacted])")
    }
}
impl TransportCipher {
    pub fn new(write_key: [u8; 32], read_key: [u8; 32]) -> Self {
        Self {
            write_key,
            read_key,
            write_counter: 0,
            read_counter: 0,
            failed: false,
        }
    }
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = (|| {
            let iv = nonce(&mut self.write_counter)?;
            Ok(crypto::aes_encrypt_gcm(data, &self.write_key, &iv, b"")?)
        })();
        if result.is_err() {
            self.write_key.zeroize();
            self.read_key.zeroize();
            self.failed = true;
        }
        result
    }
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = (|| {
            let iv = nonce(&mut self.read_counter)?;
            Ok(crypto::aes_decrypt_gcm(data, &self.read_key, &iv, b"")?)
        })();
        if result.is_err() {
            self.write_key.zeroize();
            self.read_key.zeroize();
            self.failed = true;
        }
        result
    }
}

/// Frame boundary parser; consume one frame at a time so a handshake callback
/// may transition state before an encrypted frame from the same packet is read.
#[derive(Debug)]
pub struct FrameDecoder {
    buffer: BytesMut,
    max_frame: usize,
    max_buffer: usize,
    failed: bool,
}
impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            buffer: BytesMut::new(),
            max_frame: MAX_FRAME_SIZE,
            max_buffer: 2 * (MAX_FRAME_SIZE + 3),
            failed: false,
        }
    }
}
impl FrameDecoder {
    pub fn with_limits(max_frame: usize, max_buffer: usize) -> Result<Self> {
        if max_frame > MAX_FRAME_SIZE || max_buffer < max_frame.saturating_add(3) {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            buffer: BytesMut::new(),
            max_frame,
            max_buffer,
            failed: false,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(Error::Failed);
        }
        if bytes.len() > self.max_buffer.saturating_sub(self.buffer.len()) {
            self.failed = true;
            self.buffer.clear();
            return Err(Error::BufferLimit);
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
    pub fn next_frame(&mut self) -> Result<Option<Bytes>> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.buffer.len() < 3 {
            return Ok(None);
        }
        let n = (usize::from(self.buffer[0]) << 16)
            | (usize::from(self.buffer[1]) << 8)
            | usize::from(self.buffer[2]);
        if n > self.max_frame {
            self.failed = true;
            self.buffer.clear();
            return Err(Error::FrameTooLarge);
        }
        if self.buffer.len() < n + 3 {
            return Ok(None);
        }
        Ok(Some(self.buffer.split_to(n + 3).freeze().slice(3..)))
    }
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}
#[derive(Debug)]
pub struct FrameEncoder {
    intro: Vec<u8>,
    sent_intro: bool,
}
impl FrameEncoder {
    pub fn new(header: &[u8], routing: Option<&[u8]>) -> Result<Self> {
        let mut intro = Vec::new();
        if let Some(r) = routing {
            if r.len() > MAX_FRAME_SIZE {
                return Err(Error::FrameTooLarge);
            }
            intro.extend_from_slice(b"ED\x00\x01");
            intro.extend_from_slice(&[(r.len() >> 16) as u8, (r.len() >> 8) as u8, r.len() as u8]);
            intro.extend_from_slice(r);
        }
        intro.extend_from_slice(header);
        Ok(Self {
            intro,
            sent_intro: false,
        })
    }
    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(Error::FrameTooLarge);
        }
        let mut frame =
            Vec::with_capacity(if self.sent_intro { 0 } else { self.intro.len() } + 3 + data.len());
        if !self.sent_intro {
            frame.extend_from_slice(&self.intro);
            self.sent_intro = true;
        }
        frame.extend_from_slice(&[
            (data.len() >> 16) as u8,
            (data.len() >> 8) as u8,
            data.len() as u8,
        ]);
        frame.extend_from_slice(data);
        Ok(frame)
    }
}

#[derive(Clone, Copy)]
struct TrustRoot {
    key: [u8; 32],
    issuer_serial: u32,
}
const WHATSAPP_ROOT: TrustRoot = TrustRoot {
    key: WA_ROOT,
    issuer_serial: 0,
};
fn verify_certificate(chain_bytes: &[u8], server_static: &[u8], root: TrustRoot) -> Result<()> {
    let chain = proto::CertChain::decode(chain_bytes).map_err(|_| Error::InvalidProtobuf)?;
    let leaf = chain.leaf.ok_or(Error::MissingCertificate)?;
    let intermediate = chain.intermediate.ok_or(Error::MissingCertificate)?;
    let intermediate_bytes = intermediate
        .details
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or(Error::MissingCertificate)?;
    let intermediate_signature = intermediate
        .signature
        .as_deref()
        .ok_or(Error::MissingCertificate)?;
    let details = proto::cert_chain::noise_certificate::Details::decode(intermediate_bytes)
        .map_err(|_| Error::InvalidProtobuf)?;
    if details.issuer_serial != Some(root.issuer_serial) {
        return Err(Error::InvalidIssuer);
    }
    if !crypto::verify_signature(&root.key, intermediate_bytes, intermediate_signature) {
        return Err(Error::InvalidCertificate);
    }
    let intermediate_key = details.key.as_deref().ok_or(Error::MissingCertificate)?;
    let leaf_bytes = leaf
        .details
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or(Error::MissingCertificate)?;
    let leaf_signature = leaf.signature.as_deref().ok_or(Error::MissingCertificate)?;
    if !crypto::verify_signature(intermediate_key, leaf_bytes, leaf_signature) {
        return Err(Error::InvalidCertificate);
    }
    let leaf_details = proto::cert_chain::noise_certificate::Details::decode(leaf_bytes)
        .map_err(|_| Error::InvalidProtobuf)?;
    if details.serial.is_none() || leaf_details.issuer_serial != details.serial {
        return Err(Error::InvalidIssuer);
    }
    if leaf_details.key.as_deref() != Some(server_static) {
        return Err(Error::StaticKeyMismatch);
    }
    Ok(())
}
struct Handshake {
    cipher: Transcript,
    verified: bool,
    payload_encrypted: bool,
}
enum Phase {
    Handshake(Handshake),
    Transport(TransportCipher),
    Failed,
}
pub enum Frame {
    Handshake(Bytes),
    Node(binary::Node),
}
/// Strict production session. The only trust root exposed here is WhatsApp's
/// pinned root; synthetic trust injection exists only in internal offline tests.
pub struct NoiseSession {
    ephemeral: crypto::PrivateKey,
    phase: Phase,
    encoder: FrameEncoder,
    decoder: FrameDecoder,
    root: TrustRoot,
    node_limits: binary::Limits,
}
impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.phase {
            Phase::Handshake(_) => "NoiseSession(Handshake)",
            Phase::Transport(_) => "NoiseSession(Transport)",
            Phase::Failed => "NoiseSession(Failed)",
        })
    }
}
impl NoiseSession {
    pub fn new(ephemeral: crypto::PrivateKey, routing: Option<&[u8]>) -> Result<Self> {
        Self::with_root(ephemeral, routing, WHATSAPP_ROOT)
    }
    fn with_root(
        ephemeral: crypto::PrivateKey,
        routing: Option<&[u8]>,
        root: TrustRoot,
    ) -> Result<Self> {
        let cipher = Transcript::new(&NOISE_WA_HEADER, &ephemeral.public_key());
        Ok(Self {
            ephemeral,
            phase: Phase::Handshake(Handshake {
                cipher,
                verified: false,
                payload_encrypted: false,
            }),
            encoder: FrameEncoder::new(&NOISE_WA_HEADER, routing)?,
            decoder: FrameDecoder::default(),
            root,
            node_limits: binary::Limits::default(),
        })
    }
    #[cfg(test)]
    pub(crate) fn with_test_root(
        ephemeral: crypto::PrivateKey,
        routing: Option<&[u8]>,
        key: [u8; 32],
    ) -> Result<Self> {
        Self::with_root(
            ephemeral,
            routing,
            TrustRoot {
                key,
                issuer_serial: 0,
            },
        )
    }
    pub(crate) fn set_node_limits(&mut self, limits: binary::Limits) {
        self.node_limits = limits;
    }
    pub fn client_hello(&mut self) -> Result<Vec<u8>> {
        if !matches!(
            self.phase,
            Phase::Handshake(Handshake {
                verified: false,
                ..
            })
        ) {
            return Err(Error::HandshakeOrder);
        }
        let hello = proto::HandshakeMessage {
            client_hello: Some(proto::handshake_message::ClientHello {
                ephemeral: Some(self.ephemeral.public_key().to_vec()),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.encode_frame(&hello.encode_to_vec())
    }
    pub fn process_handshake(
        &mut self,
        hello: &proto::handshake_message::ServerHello,
        static_key: &crypto::PrivateKey,
    ) -> Result<Vec<u8>> {
        let phase = std::mem::replace(&mut self.phase, Phase::Failed);
        let Phase::Handshake(mut h) = phase else {
            return Err(Error::HandshakeOrder);
        };
        if h.verified {
            return Err(Error::HandshakeOrder);
        }
        let ephemeral = hello
            .ephemeral
            .as_deref()
            .filter(|b| b.len() == 32)
            .ok_or(Error::InvalidHandshake)?;
        h.cipher.authenticate(ephemeral);
        let shared = Zeroizing::new(self.ephemeral.shared_key(ephemeral)?);
        h.cipher.mix_key(shared.as_ref())?;
        let static_decrypted = Zeroizing::new(
            h.cipher
                .decrypt(hello.r#static.as_deref().ok_or(Error::InvalidHandshake)?)?,
        );
        if static_decrypted.len() != 32 {
            return Err(Error::InvalidHandshake);
        }
        let shared = Zeroizing::new(self.ephemeral.shared_key(&static_decrypted)?);
        h.cipher.mix_key(shared.as_ref())?;
        let cert = Zeroizing::new(
            h.cipher
                .decrypt(hello.payload.as_deref().ok_or(Error::InvalidHandshake)?)?,
        );
        verify_certificate(&cert, &static_decrypted, self.root)?;
        let key_encrypted = h.cipher.encrypt(&static_key.public_key())?;
        let shared = Zeroizing::new(static_key.shared_key(ephemeral)?);
        h.cipher.mix_key(shared.as_ref())?;
        h.verified = true;
        self.phase = Phase::Handshake(h);
        Ok(key_encrypted)
    }
    pub fn encrypt_client_payload(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let result = match &mut self.phase {
            Phase::Handshake(h) if h.verified && !h.payload_encrypted => {
                h.cipher.encrypt(plaintext).inspect(|_| {
                    h.payload_encrypted = true;
                })
            }
            Phase::Failed => Err(Error::Failed),
            _ => Err(Error::HandshakeOrder),
        };
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    pub fn finish_init(&mut self) -> Result<()> {
        let phase = std::mem::replace(&mut self.phase, Phase::Failed);
        if let Phase::Handshake(h) = phase
            && h.verified
            && h.payload_encrypted
        {
            self.phase = Phase::Transport(h.cipher.finish()?);
            self.ephemeral.zeroize();
            return Ok(());
        }
        Err(Error::HandshakeOrder)
    }
    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let result = match &mut self.phase {
            Phase::Failed => Err(Error::Failed),
            Phase::Handshake(_) => self.encoder.encode(data),
            Phase::Transport(t) => {
                if data.len() > MAX_FRAME_SIZE - 16 {
                    return Err(Error::FrameTooLarge);
                }
                t.encrypt(data).and_then(|c| self.encoder.encode(&c))
            }
        };
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    pub fn push_bytes(&mut self, data: &[u8]) -> Result<()> {
        if matches!(self.phase, Phase::Failed) {
            return Err(Error::Failed);
        }
        if let Err(e) = self.decoder.push(data) {
            self.phase = Phase::Failed;
            return Err(e);
        }
        Ok(())
    }
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if matches!(self.phase, Phase::Failed) {
            return Err(Error::Failed);
        }
        let result = (|| {
            let Some(frame) = self.decoder.next_frame()? else {
                return Ok(None);
            };
            Ok(Some(match &mut self.phase {
                Phase::Handshake(_) => Frame::Handshake(frame),
                Phase::Transport(t) => Frame::Node(binary::decode_with_limits(
                    &t.decrypt(&frame)?,
                    self.node_limits,
                )?),
                Phase::Failed => return Err(Error::Failed),
            }))
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/noise-upstream.json")).unwrap()
    }
    fn bytes(v: &Value) -> Vec<u8> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect()
    }
    fn private(v: &Value) -> crypto::PrivateKey {
        crypto::PrivateKey::from_bytes(bytes(v).try_into().unwrap())
    }
    fn session(row: &Value) -> NoiseSession {
        let routing = (!row["routing"].is_null()).then(|| bytes(&row["routing"]));
        NoiseSession::with_root(
            private(&row["clientPrivate"]),
            routing.as_deref(),
            TrustRoot {
                key: bytes(&row["rootPublic"]).try_into().unwrap(),
                issuer_serial: 0,
            },
        )
        .unwrap()
    }
    fn hello(v: &Value) -> proto::handshake_message::ServerHello {
        proto::HandshakeMessage::decode(bytes(v).as_slice())
            .unwrap()
            .server_hello
            .unwrap()
    }
    fn assert_node(frame: Option<Frame>, expected: &Value) {
        let Some(Frame::Node(n)) = frame else {
            panic!("expected authenticated node")
        };
        let attrs: serde_json::Map<String, Value> =
            n.attrs.into_iter().map(|(k, v)| (k, json!(v))).collect();
        assert_eq!(json!({"tag":n.tag,"attrs":attrs,"content":null}), *expected);
        assert!(n.content.is_none());
    }
    fn initialize(s: &mut NoiseSession, row: &Value) {
        assert_eq!(s.client_hello().unwrap(), bytes(&row["clientHelloFrame"]));
        let encrypted = s
            .process_handshake(
                &hello(&row["serverHello"]),
                &private(&row["clientStaticPrivate"]),
            )
            .unwrap();
        assert_eq!(encrypted, bytes(&row["keyEncrypted"]));
        let payload = s
            .encrypt_client_payload(&bytes(&row["clientPayload"]))
            .unwrap();
        assert_eq!(payload, bytes(&row["payloadEncrypted"]));
        let finish = proto::HandshakeMessage {
            client_finish: Some(proto::handshake_message::ClientFinish {
                r#static: Some(encrypted),
                payload: Some(payload),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            s.encode_frame(&finish.encode_to_vec()).unwrap(),
            bytes(&row["clientFinishFrame"])
        );
        s.finish_init().unwrap();
    }
    #[test]
    fn complete_offline_handshakes_and_transport_match_original() {
        let f = fixture();
        assert_eq!(f["upstream_commit"], crate::UPSTREAM_COMMIT);
        assert_eq!(bytes(&f["realWaRootPublic"]), WA_ROOT);
        assert_eq!(bytes(&f["header"]), NOISE_WA_HEADER);
        for row in f["cases"].as_array().unwrap() {
            let mut s = session(row);
            // Coalesced handshake and transport bytes must be decoded with different states.
            let mut coalesced = bytes(&row["serverHelloFrame"]);
            coalesced.extend(bytes(&row["incoming"][0]["frame"]));
            s.push_bytes(&coalesced).unwrap();
            let Some(Frame::Handshake(h)) = s.next_frame().unwrap() else {
                panic!("handshake")
            };
            assert_eq!(h.as_ref(), bytes(&row["serverHello"]));
            initialize(&mut s, row);
            assert_node(s.next_frame().unwrap(), &row["incoming"][0]["node"]);
            for outgoing in row["outgoing"].as_array().unwrap() {
                assert_eq!(
                    s.encode_frame(&bytes(&outgoing["plaintext"])).unwrap(),
                    bytes(&outgoing["frame"])
                );
            }
            for incoming in row["incoming"].as_array().unwrap().iter().skip(1) {
                let wire = bytes(&incoming["frame"]);
                for (i, b) in wire.iter().enumerate() {
                    s.push_bytes(&[*b]).unwrap();
                    let result = s.next_frame().unwrap();
                    if i + 1 == wire.len() {
                        assert_node(result, &incoming["node"]);
                    } else {
                        assert!(result.is_none());
                    }
                }
            }
            assert_eq!(s.decoder.buffered_len(), 0);
        }
    }
    #[test]
    fn untrusted_and_malformed_certificates_never_enter_transport() {
        let f = fixture();
        let row = &f["cases"][0];
        for case in f["negative"].as_array().unwrap() {
            let mut s = session(row);
            let err = s
                .process_handshake(
                    &hello(&case["serverHello"]),
                    &private(&row["clientStaticPrivate"]),
                )
                .unwrap_err();
            assert_eq!(
                format!("{err:?}"),
                case["expectedError"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert!(s.finish_init().is_err());
            assert_eq!(s.encode_frame(b"x"), Err(Error::Failed));
            assert_eq!(s.push_bytes(&[]), Err(Error::Failed));
        }
        let mut production = NoiseSession::new(private(&row["clientPrivate"]), None).unwrap();
        assert_eq!(
            production.process_handshake(
                &hello(&row["serverHello"]),
                &private(&row["clientStaticPrivate"])
            ),
            Err(Error::InvalidCertificate)
        );
    }
    #[test]
    fn authentication_failure_and_replay_are_terminal() {
        let f = fixture();
        let row = &f["cases"][0];
        for corrupt in [true, false] {
            let mut s = session(row);
            initialize(&mut s, row);
            let mut wire = bytes(&row["incoming"][0]["frame"]);
            if corrupt {
                *wire.last_mut().unwrap() ^= 1;
            } else {
                s.push_bytes(&wire).unwrap();
                assert!(s.next_frame().unwrap().is_some());
            }
            s.push_bytes(&wire).unwrap();
            assert!(s.next_frame().is_err());
            assert!(matches!(s.next_frame(), Err(Error::Failed)));
        }
        let mut s = session(row);
        let mut h = hello(&row["serverHello"]);
        h.payload.as_mut().unwrap()[0] ^= 1;
        assert!(
            s.process_handshake(&h, &private(&row["clientStaticPrivate"]))
                .is_err()
        );
        assert!(s.finish_init().is_err());
        let mut s = session(row);
        assert!(s.finish_init().is_err());
        assert!(s.encode_frame(b"x").is_err());
        let mut s = session(row);
        assert!(s.encrypt_client_payload(b"x").is_err());
        assert!(s.finish_init().is_err());
    }
    #[test]
    fn counters_never_wrap_or_reuse_nonces() {
        let mut t = TransportCipher::new([1; 32], [2; 32]);
        t.write_counter = u64::from(u32::MAX);
        assert!(t.encrypt(b"last").is_ok());
        assert_eq!(t.encrypt(b"overflow"), Err(Error::CounterExhausted));
        assert_eq!(t.encrypt(b"retry"), Err(Error::Failed));
        let mut t = TransportCipher::new([1; 32], [2; 32]);
        t.read_counter = u64::from(u32::MAX);
        let mut iv = [0; 12];
        iv[8..].copy_from_slice(&u32::MAX.to_be_bytes());
        let ciphertext = crypto::aes_encrypt_gcm(b"last", &[2; 32], &iv, b"").unwrap();
        assert_eq!(t.decrypt(&ciphertext).unwrap(), b"last");
        assert_eq!(t.decrypt(&ciphertext), Err(Error::CounterExhausted));
        assert_eq!(t.decrypt(&ciphertext), Err(Error::Failed));
    }
    #[test]
    fn handshake_payload_is_required_and_cannot_be_encrypted_twice() {
        let f = fixture();
        let row = &f["cases"][0];
        let mut s = session(row);
        s.process_handshake(
            &hello(&row["serverHello"]),
            &private(&row["clientStaticPrivate"]),
        )
        .unwrap();
        assert_eq!(s.finish_init(), Err(Error::HandshakeOrder));
        let mut s = session(row);
        s.process_handshake(
            &hello(&row["serverHello"]),
            &private(&row["clientStaticPrivate"]),
        )
        .unwrap();
        s.encrypt_client_payload(b"one payload").unwrap();
        assert_eq!(
            s.encrypt_client_payload(b"second"),
            Err(Error::HandshakeOrder)
        );
        assert_eq!(s.encode_frame(b"retry"), Err(Error::Failed));
    }
    #[test]
    fn coalesced_plaintext_frames_preserve_order_and_partial_tail() {
        let mut decoder = FrameDecoder::default();
        let mut encoder = FrameEncoder::new(&[], None).unwrap();
        let payloads: Vec<Vec<u8>> = (0..100)
            .map(|n| format!("frame-{n}").into_bytes())
            .collect();
        let mut packet = Vec::new();
        for payload in &payloads {
            packet.extend(encoder.encode(payload).unwrap());
        }
        packet.extend([0, 0, 2, 7]);
        decoder.push(&packet).unwrap();
        for payload in payloads {
            assert_eq!(decoder.next_frame().unwrap().unwrap().as_ref(), payload);
        }
        assert!(decoder.next_frame().unwrap().is_none());
        decoder.push(&[8]).unwrap();
        assert_eq!(decoder.next_frame().unwrap().unwrap().as_ref(), [7, 8]);
    }
    #[test]
    fn framing_bounds_fragmentation_and_intro() {
        let mut encoder = FrameEncoder::new(&NOISE_WA_HEADER, Some(&[])).unwrap();
        assert_eq!(
            encoder.encode(b"a").unwrap(),
            [b"ED\0\x01\0\0\0WA\x06\x03\0\0\x01".as_slice(), b"a"].concat()
        );
        assert_eq!(encoder.encode(&[]).unwrap(), [0, 0, 0]);
        let mut decoder = FrameDecoder::with_limits(4, 14).unwrap();
        for b in [0, 0, 4, 1, 2, 3] {
            decoder.push(&[b]).unwrap();
            assert!(decoder.next_frame().unwrap().is_none());
        }
        decoder.push(&[4, 0, 0, 0]).unwrap();
        assert_eq!(
            decoder.next_frame().unwrap().unwrap().as_ref(),
            [1, 2, 3, 4]
        );
        assert!(decoder.next_frame().unwrap().unwrap().is_empty());
        decoder.push(&[0, 0, 5]).unwrap();
        assert_eq!(decoder.next_frame(), Err(Error::FrameTooLarge));
        assert_eq!(decoder.push(&[]), Err(Error::Failed));
        let mut decoder = FrameDecoder::with_limits(4, 7).unwrap();
        assert_eq!(decoder.push(&[0; 8]), Err(Error::BufferLimit));
        assert_eq!(decoder.next_frame(), Err(Error::Failed));
        assert!(FrameDecoder::with_limits(4, 6).is_err());
        assert!(FrameDecoder::with_limits(MAX_FRAME_SIZE + 1, usize::MAX).is_err());
    }
}
