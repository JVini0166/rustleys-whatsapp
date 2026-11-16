//! Durable signed-prekey history and acknowledgement-gated rotation.
//! Retain pending keys: a lost acknowledgement does not prove non-delivery.
use crate::{
    auth::{Bytes, Credentials, KeyPair, SignedKeyPair},
    binary::{Content, Node},
    crypto,
    signal::{Error, Result, Store, Transaction},
};
use wacore_libsignal::engine::{self, codec};
use zeroize::Zeroizing;
const ACTIVE: &str = "signed-prekey-active";
const NEXT: &str = "signed-prekey-next";
const MAX: u32 = 0xff_ffff;
fn counter(tx: &dyn Transaction, name: &str) -> Result<u32> {
    let bytes = tx.get("meta", name)?.ok_or(Error::InvalidKey)?;
    Ok(u32::from_be_bytes(
        bytes.as_slice().try_into().map_err(|_| Error::InvalidKey)?,
    ))
}
fn put_counter(tx: &mut dyn Transaction, name: &str, value: u32) -> Result<()> {
    tx.put("meta", name, &value.to_be_bytes())
}
fn record(key: &SignedKeyPair) -> Result<engine::SignedPreKeyRecord> {
    key.key_pair.validate()?;
    if key.key_id > MAX {
        return Err(Error::PreKeyIdExhausted);
    }
    Ok(engine::SignedPreKeyRecord {
        id: key.key_id,
        key_pair: engine::KeyPair {
            public: key
                .key_pair
                .public
                .expose()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
            private: key
                .key_pair
                .private
                .expose()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        },
        signature: key
            .signature
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
        timestamp: key.timestamp_s.unwrap_or(0),
    })
}
fn export(record: engine::SignedPreKeyRecord) -> SignedKeyPair {
    SignedKeyPair {
        key_pair: KeyPair {
            public: Bytes::new(record.key_pair.public.to_vec()),
            private: Bytes::new(record.key_pair.private.to_vec()),
        },
        signature: Bytes::new(record.signature.to_vec()),
        key_id: record.id,
        timestamp_s: (record.timestamp != 0).then_some(record.timestamp),
    }
}
pub(crate) fn load(
    tx: &dyn Transaction,
    identity: &[u8; 32],
    id: u32,
) -> Result<engine::SignedPreKeyRecord> {
    let bytes = tx
        .get("signed-pre-key", &id.to_string())?
        .ok_or(Error::MissingSignedPreKey)?;
    let record = codec::decode_signed_pre_key(&bytes)?;
    if id > MAX
        || record.id != id
        || crypto::PrivateKey::from_bytes(record.key_pair.private).public_key()
            != record.key_pair.public
        || !crypto::verify_signature(
            identity,
            &crypto::generate_signal_pub_key(&record.key_pair.public),
            &record.signature,
        )
    {
        return Err(Error::InvalidKey);
    }
    Ok(record)
}
pub(crate) fn active(tx: &dyn Transaction, identity: &[u8; 32]) -> Result<SignedKeyPair> {
    Ok(export(load(tx, identity, counter(tx, ACTIVE)?)?))
}
// Called inside the same transaction as identity binding. Persisting stale JSON
// may add history but must never reactivate a previously retired key.
pub(crate) fn initialize(tx: &mut dyn Transaction, creds: &Credentials) -> Result<()> {
    let identity = creds
        .signed_identity_key
        .public
        .expose()
        .try_into()
        .map_err(|_| Error::InvalidKey)?;
    let supplied = record(&creds.signed_pre_key)?;
    if tx
        .get("signed-pre-key", &supplied.id.to_string())?
        .is_some()
    {
        let saved = load(tx, identity, supplied.id)?;
        if saved.key_pair.public != supplied.key_pair.public
            || saved.key_pair.private != supplied.key_pair.private
        {
            return Err(Error::SignedPreKeyConflict);
        }
    } else {
        let encoded = Zeroizing::new(codec::encode_signed_pre_key(&supplied));
        tx.put("signed-pre-key", &supplied.id.to_string(), &encoded)?;
    }
    if tx.get("meta", ACTIVE)?.is_none() {
        if tx.get("meta", NEXT)?.is_some() {
            return Err(Error::InvalidKey);
        }
        put_counter(tx, ACTIVE, supplied.id)?;
        put_counter(tx, NEXT, supplied.id + 1)?;
    } else {
        let active = counter(tx, ACTIVE)?;
        load(tx, identity, active)?;
        let next = counter(tx, NEXT)?;
        if next <= active || next > MAX + 1 {
            return Err(Error::InvalidKey);
        }
        if supplied.id >= next {
            put_counter(tx, NEXT, supplied.id + 1)?;
        }
    }
    Ok(())
}
/// A durable reservation. Private material stays in the store; Debug is public only.
#[derive(Debug)]
pub struct Rotation {
    id: u32,
    previous_id: u32,
    identity: [u8; 32],
    registration: u16,
    node: Node,
}
impl Rotation {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn previous_id(&self) -> u32 {
        self.previous_id
    }
    pub fn node(&self) -> &Node {
        &self.node
    }
}
pub struct Authority<S: Store> {
    store: S,
    identity: KeyPair,
    registration: u16,
}
impl<S: Store> std::fmt::Debug for Authority<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedPreKeyAuthority([redacted])")
    }
}
impl<S: Store> Authority<S> {
    pub fn new(creds: &Credentials, store: S) -> Result<Self> {
        creds.validate()?;
        let mut binding = creds.signed_identity_key.public.expose().to_vec();
        binding.extend(u32::from(creds.registration_id).to_be_bytes());
        store.transaction(|tx| {
            match tx.get("meta", "local-identity")? {
                Some(existing) if existing.as_slice() != binding => {
                    return Err(Error::LocalIdentityMismatch);
                }
                Some(_) => {}
                None => tx.put("meta", "local-identity", &binding)?,
            }
            initialize(tx, creds)
        })?;
        Ok(Self {
            store,
            identity: creds.signed_identity_key.clone(),
            registration: creds.registration_id,
        })
    }
    fn public(&self) -> &[u8; 32] {
        self.identity
            .public
            .expose()
            .try_into()
            .expect("validated identity")
    }
    pub fn active_key(&self) -> Result<SignedKeyPair> {
        self.store.transaction(|tx| active(tx, self.public()))
    }
    /// Explicit private-key export; returned key fields have redacted Debug.
    pub fn history_key(&self, id: u32) -> Result<SignedKeyPair> {
        self.store
            .transaction(|tx| Ok(export(load(tx, self.public(), id)?)))
    }
    pub fn prepare_rotation(&self) -> Result<Rotation> {
        self.store.transaction(|tx| {
            let previous_id = counter(tx, ACTIVE)?;
            load(tx, self.public(), previous_id)?;
            let id = counter(tx, NEXT)?;
            if id > MAX {
                return Err(Error::PreKeyIdExhausted);
            }
            if id <= previous_id || tx.get("signed-pre-key", &id.to_string())?.is_some() {
                return Err(Error::SignedPreKeyConflict);
            }
            let generated = crypto::signed_key_pair(&self.identity.private_key()?, id)
                .map_err(|_| Error::InvalidKey)?;
            let key = SignedKeyPair {
                key_pair: KeyPair::from_private(&generated.private_key),
                signature: Bytes::new(generated.signature.to_vec()),
                key_id: id,
                timestamp_s: None,
            };
            let encoded = Zeroizing::new(codec::encode_signed_pre_key(&record(&key)?));
            tx.put("signed-pre-key", &id.to_string(), &encoded)?;
            tx.put(
                "signed-pre-key-pending",
                &id.to_string(),
                &previous_id.to_be_bytes(),
            )?;
            put_counter(tx, NEXT, id + 1)?;
            Ok(Rotation {
                id,
                previous_id,
                identity: *self.public(),
                registration: self.registration,
                node: Node {
                    tag: "iq".into(),
                    attrs: vec![
                        ("to".into(), crate::jid::S_WHATSAPP_NET.into()),
                        ("type".into(), "set".into()),
                        ("xmlns".into(), "encrypt".into()),
                    ],
                    content: Some(Content::Nodes(vec![Node {
                        tag: "rotate".into(),
                        attrs: vec![],
                        content: Some(Content::Nodes(vec![
                            crate::prekeys::xmpp_signed_pre_key(&key)
                                .map_err(|_| Error::InvalidKey)?,
                        ])),
                    }])),
                },
            })
        })
    }
    /// Call only after the server acknowledges this exact rotate IQ. A transport
    /// error leaves the candidate durable and decryptable, without activating it.
    pub fn confirm(&self, rotation: &Rotation) -> Result<()> {
        if rotation.identity != *self.public() || rotation.registration != self.registration {
            return Err(Error::LocalIdentityMismatch);
        }
        self.store.transaction(|tx| {
            let active = counter(tx, ACTIVE)?;
            load(tx, self.public(), rotation.id)?;
            if active == rotation.id {
                return Ok(());
            }
            let pending = tx
                .get("signed-pre-key-pending", &rotation.id.to_string())?
                .ok_or(Error::SignedPreKeyConflict)?;
            if active != rotation.previous_id
                || pending.as_slice() != rotation.previous_id.to_be_bytes()
            {
                return Err(Error::SignedPreKeyConflict);
            }
            put_counter(tx, ACTIVE, rotation.id)?;
            tx.remove("signed-pre-key-pending", &rotation.id.to_string())
        })
    }
    /// Project authoritative state into a credentials snapshot for JSON storage.
    /// Persist the snapshot using the host's normal compare-and-save mechanism.
    pub fn sync_credentials(&self, creds: &mut Credentials) -> Result<()> {
        creds.validate()?;
        if creds.signed_identity_key.public.expose() != self.public()
            || creds.registration_id != self.registration
        {
            return Err(Error::LocalIdentityMismatch);
        }
        creds.signed_pre_key = self.active_key()?;
        Ok(())
    }
}

/// Cancel-safe async socket facade. Share the same Manager with Uploader so
/// normal prekey uploads cannot publish an obsolete signed key during rotation.
/// One account still needs one transport owner; this is not a distributed lease.
pub struct Rotator<S: Store, Q> {
    context: std::sync::Arc<RotationContext<S, Q>>,
}
struct RotationContext<S: Store, Q> {
    authority: std::sync::Arc<Authority<S>>,
    manager: std::sync::Arc<crate::prekeys::Manager<S>>,
    endpoint: Q,
    timeout: std::time::Duration,
}
impl<S: Store, Q> Clone for Rotator<S, Q> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}
impl<S: Store, Q> std::fmt::Debug for Rotator<S, Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedPreKeyRotator([redacted])")
    }
}
impl<S: Store + Clone + Send + Sync + 'static, Q: crate::prekeys::Query> Rotator<S, Q> {
    /// The source query deadline defaults to 60 seconds. Caller-provided bounds
    /// must be nonzero and at most five minutes, including publication lock wait.
    pub fn new(
        creds: &Credentials,
        manager: std::sync::Arc<crate::prekeys::Manager<S>>,
        endpoint: Q,
        timeout: std::time::Duration,
    ) -> std::result::Result<Self, crate::prekeys::Error> {
        use crate::prekeys::Error;
        if timeout.is_zero() || timeout > std::time::Duration::from_secs(300) {
            return Err(Error::InvalidPolicy);
        }
        if creds.signed_identity_key.public.expose() != manager.identity
            || creds.registration_id != manager.registration
        {
            return Err(Error::CredentialConflict);
        }
        let authority = Authority::new(creds, manager.store.clone())?;
        Ok(Self {
            context: std::sync::Arc::new(RotationContext {
                authority: std::sync::Arc::new(authority),
                manager,
                endpoint,
                timeout,
            }),
        })
    }
    /// Once started, cancellation of the waiting caller does not drop the
    /// publication lock early or lose a successful server acknowledgement.
    pub async fn rotate(&self) -> std::result::Result<SignedKeyPair, crate::prekeys::Error> {
        use crate::prekeys::Error;
        use futures_util::FutureExt;
        let context = self.context.clone();
        tokio::spawn(async move {
            let timeout = context.timeout;
            tokio::time::timeout(
                timeout,
                std::panic::AssertUnwindSafe(async move {
                    let _publication = context.manager.publication.lock().await;
                    let authority = context.authority.clone();
                    let rotation =
                        tokio::task::spawn_blocking(move || authority.prepare_rotation())
                            .await
                            .map_err(|_| Error::Worker)??;
                    context
                        .endpoint
                        .query(rotation.node().clone())
                        .await
                        .map_err(Error::Network)?;
                    let authority = context.authority.clone();
                    tokio::task::spawn_blocking(move || {
                        authority.confirm(&rotation)?;
                        authority.active_key()
                    })
                    .await
                    .map_err(|_| Error::Worker)?
                    .map_err(Error::from)
                })
                .catch_unwind(),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Worker)?
        })
        .await
        .map_err(|_| Error::Worker)?
    }
}
