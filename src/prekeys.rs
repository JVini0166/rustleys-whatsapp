//! Baileys prekey planning, native atomic reservation and login bootstrap.
//! Blocking storage/key generation must execute off the network executor.
use crate::{
    auth::{Bytes, Credentials, KeyPair},
    binary::{Content, Node},
    signal::{self, Store},
    socket,
};
use futures_util::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use std::{
    collections::BTreeMap, future::Future, panic::AssertUnwindSafe, sync::Arc, time::Duration,
};
use tokio::{sync::Mutex, time::Instant};
use wacore_libsignal::engine::{self, codec};
use zeroize::Zeroizing;
pub const MIN_PREKEY_COUNT: u32 = 5;
pub const INITIAL_PREKEY_COUNT: u32 = 812;
pub const MAX_PREKEY_ID: u32 = 0xff_ffff;
pub const MAX_BATCH: u32 = 8192;
#[derive(Debug, Clone)]
pub enum Error {
    InvalidCount,
    InvalidPolicy,
    InvalidCounters,
    Exhausted,
    InvalidKey,
    MissingKey,
    KeyCollision,
    CredentialConflict,
    InvalidResponse,
    MissingDigest,
    Worker,
    Timeout,
    Storage(Arc<signal::Error>),
    Network(socket::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Prekeys: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<signal::Error> for Error {
    fn from(error: signal::Error) -> Self {
        Self::Storage(Arc::new(error))
    }
}
impl From<socket::Error> for Error {
    fn from(error: socket::Error) -> Self {
        Self::Network(error)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counters {
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
}
impl Counters {
    pub fn from_credentials(creds: &Credentials) -> Self {
        Self {
            next_pre_key_id: creds.next_pre_key_id,
            first_unuploaded_pre_key_id: creds.first_unuploaded_pre_key_id,
        }
    }
    fn validate(self) -> Result<()> {
        if self.first_unuploaded_pre_key_id > self.next_pre_key_id
            || self.next_pre_key_id > MAX_PREKEY_ID + 1
        {
            Err(Error::InvalidCounters)
        } else {
            Ok(())
        }
    }
    fn encode(self) -> [u8; 8] {
        let mut out = [0; 8];
        out[..4].copy_from_slice(&self.next_pre_key_id.to_be_bytes());
        out[4..].copy_from_slice(&self.first_unuploaded_pre_key_id.to_be_bytes());
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 8 {
            return Err(Error::InvalidCounters);
        }
        let result = Self {
            next_pre_key_id: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            first_unuploaded_pre_key_id: u32::from_be_bytes(bytes[4..].try_into().unwrap()),
        };
        result.validate()?;
        Ok(result)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub first: u32,
    pub end: u32,
    pub generate_from: u32,
    pub counters: Counters,
}
pub fn plan(counters: Counters, count: u32) -> Result<Plan> {
    counters.validate()?;
    if count == 0 || count > MAX_BATCH {
        return Err(Error::InvalidCount);
    }
    let end = counters
        .first_unuploaded_pre_key_id
        .checked_add(count)
        .ok_or(Error::Exhausted)?;
    if end > MAX_PREKEY_ID + 1 {
        return Err(Error::Exhausted);
    }
    Ok(Plan {
        first: counters.first_unuploaded_pre_key_id,
        end,
        generate_from: counters.next_pre_key_id,
        counters: Counters {
            next_pre_key_id: counters.next_pre_key_id.max(end),
            first_unuploaded_pre_key_id: end,
        },
    })
}
fn child(tag: &str, content: Content) -> Node {
    Node {
        tag: tag.into(),
        attrs: vec![],
        content: Some(content),
    }
}
fn data(tag: &str, bytes: impl Into<Vec<u8>>) -> Node {
    child(tag, Content::Bytes(bytes.into()))
}
pub fn xmpp_pre_key(pair: &KeyPair, id: u32) -> Result<Node> {
    pair.validate().map_err(|_| Error::InvalidKey)?;
    if id > MAX_PREKEY_ID {
        return Err(Error::Exhausted);
    }
    Ok(pre_key_node(pair.public.expose(), id))
}
fn pre_key_node(public: &[u8], id: u32) -> Node {
    child(
        "key",
        Content::Nodes(vec![
            data("id", id.to_be_bytes()[1..].to_vec()),
            data("value", public.to_vec()),
        ]),
    )
}

pub fn xmpp_signed_pre_key(key: &crate::auth::SignedKeyPair) -> Result<Node> {
    key.key_pair.validate().map_err(|_| Error::InvalidKey)?;
    if key.key_id > MAX_PREKEY_ID || key.signature.expose().len() != 64 {
        return Err(Error::InvalidKey);
    }
    Ok(child(
        "skey",
        Content::Nodes(vec![
            data("id", key.key_id.to_be_bytes()[1..].to_vec()),
            data("value", key.key_pair.public.expose().to_vec()),
            data("signature", key.signature.expose().to_vec()),
        ]),
    ))
}
#[derive(Debug)]
pub struct Prepared {
    pub node: Node,
    pub first: u32,
    pub count: u32,
    pub counters: Counters,
}
/// The native metadata counters are authoritative after initialization. Stale
/// lower JSON counters are tolerated; higher ones require explicit reconciliation.
pub struct Manager<S: Store> {
    pub(crate) store: S,
    pub(crate) identity: [u8; 32],
    pub(crate) registration: u16,
    pub(crate) publication: Mutex<()>,
}
impl<S: Store> std::fmt::Debug for Manager<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreKeyManager([redacted])")
    }
}
const CURSORS: &str = "prekey-cursors";
fn storage(error: Error) -> signal::Error {
    match error {
        Error::Storage(error) => Arc::try_unwrap(error).unwrap_or(signal::Error::Storage),
        Error::Exhausted => signal::Error::PreKeyIdExhausted,
        Error::InvalidKey => signal::Error::InvalidKey,
        _ => signal::Error::InvalidPreKeyState,
    }
}
impl<S: Store> Manager<S> {
    pub fn new(creds: &Credentials, store: S) -> Result<Self> {
        creds.validate().map_err(|_| Error::InvalidKey)?;
        let initial = Counters::from_credentials(creds);
        initial.validate()?;
        let identity: [u8; 32] = creds
            .signed_identity_key
            .public
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let mut binding = identity.to_vec();
        binding.extend(u32::from(creds.registration_id).to_be_bytes());
        xmpp_signed_pre_key(&creds.signed_pre_key)?;
        store.transaction(|tx| {
            if let Some(existing) = tx.get("meta", "local-identity")? {
                if existing.as_slice() != binding {
                    return Err(signal::Error::LocalIdentityMismatch);
                }
            } else {
                tx.put("meta", "local-identity", &binding)?;
            }
            crate::signed_keys::initialize(tx, creds)?;
            if let Some(existing) = tx.get("meta", CURSORS)? {
                let saved = Counters::decode(&existing).map_err(storage)?;
                if initial.next_pre_key_id > saved.next_pre_key_id
                    || initial.first_unuploaded_pre_key_id > saved.first_unuploaded_pre_key_id
                {
                    return Err(signal::Error::PreKeyCounterConflict);
                }
            } else {
                tx.put("meta", CURSORS, &initial.encode())?;
            }
            Ok(())
        })?;
        Ok(Self {
            store,
            identity,
            registration: creds.registration_id,
            publication: Mutex::new(()),
        })
    }
    pub fn counters(&self) -> Result<Counters> {
        self.store
            .transaction(|tx| {
                let bytes = tx
                    .get("meta", CURSORS)?
                    .ok_or(signal::Error::InvalidPreKeyState)?;
                Counters::decode(&bytes).map_err(storage)
            })
            .map_err(Into::into)
    }
    /// Export explicitly requested private prekeys. The upper bound is exclusive.
    /// Missing rows remain None; diagnostics on KeyPair/Bytes are redacted.
    pub fn get_pre_keys(&self, first: u32, end: u32) -> Result<BTreeMap<u32, Option<KeyPair>>> {
        if end < first || end - first > MAX_BATCH || end > MAX_PREKEY_ID + 1 {
            return Err(Error::InvalidCount);
        }
        self.store
            .transaction(|tx| {
                let ids: Vec<_> = (first..end).map(|id| id.to_string()).collect();
                let borrowed: Vec<_> = ids.iter().map(String::as_str).collect();
                let rows = tx.get_many("pre-key", &borrowed)?;
                let mut out = BTreeMap::new();
                for id in first..end {
                    out.insert(
                        id,
                        rows.get(&id.to_string())
                            .map(|bytes| decode_key(id, bytes))
                            .transpose()
                            .map_err(storage)?,
                    );
                }
                Ok(out)
            })
            .map_err(Into::into)
    }
    pub fn current_pre_key(&self) -> Result<(u32, bool)> {
        self.store
            .transaction(|tx| {
                let bytes = tx
                    .get("meta", CURSORS)?
                    .ok_or(signal::Error::InvalidPreKeyState)?;
                let counters = Counters::decode(&bytes).map_err(storage)?;
                let id = counters.next_pre_key_id.saturating_sub(1);
                Ok((id, id > 0 && tx.get("pre-key", &id.to_string())?.is_some()))
            })
            .map_err(Into::into)
    }
    pub fn sync_counters(&self, creds: &mut Credentials) -> Result<()> {
        if creds.signed_identity_key.public.expose() != self.identity
            || creds.registration_id != self.registration
        {
            return Err(Error::CredentialConflict);
        }
        let counters = self.counters()?;
        let current = Counters::from_credentials(creds);
        if current.next_pre_key_id > counters.next_pre_key_id
            || current.first_unuploaded_pre_key_id > counters.first_unuploaded_pre_key_id
        {
            return Err(Error::CredentialConflict);
        }
        creds.next_pre_key_id = counters.next_pre_key_id;
        creds.first_unuploaded_pre_key_id = counters.first_unuploaded_pre_key_id;
        Ok(())
    }
    pub fn prepare(&self, count: u32) -> Result<Prepared> {
        // Validate before entering the backend. No network operation is performed here.
        if count == 0 || count > MAX_BATCH {
            return Err(Error::InvalidCount);
        }
        self.store
            .transaction(|tx| {
                let bytes = tx
                    .get("meta", CURSORS)?
                    .ok_or(signal::Error::InvalidPreKeyState)?;
                let plan =
                    plan(Counters::decode(&bytes).map_err(storage)?, count).map_err(storage)?;
                let mut fresh = BTreeMap::new();
                for id in plan.generate_from..plan.end {
                    if tx.get("pre-key", &id.to_string())?.is_some() {
                        return Err(signal::Error::PreKeyCollision);
                    }
                    let pair = KeyPair::generate().map_err(|_| signal::Error::InvalidKey)?;
                    let key_pair = engine::KeyPair {
                        public: pair
                            .public
                            .expose()
                            .try_into()
                            .map_err(|_| signal::Error::InvalidKey)?,
                        private: pair
                            .private
                            .expose()
                            .try_into()
                            .map_err(|_| signal::Error::InvalidKey)?,
                    };
                    fresh.insert(id, key_pair.public);
                    let encoded = Zeroizing::new(codec::encode_pre_key(&engine::PreKeyRecord {
                        id,
                        key_pair,
                    }));
                    tx.put("pre-key", &id.to_string(), &encoded)?;
                }
                // Newly generated keys are already validated by construction; do
                // not reread/derive their public keys just to build the upload.
                let ids: Vec<_> = (plan.first..plan.end.min(plan.generate_from))
                    .map(|id| id.to_string())
                    .collect();
                let borrowed: Vec<_> = ids.iter().map(String::as_str).collect();
                let rows = tx.get_many("pre-key", &borrowed)?;
                let mut list = Vec::with_capacity(count as usize);
                for id in plan.first..plan.end {
                    if let Some(public) = fresh.get(&id) {
                        list.push(pre_key_node(public, id));
                    } else {
                        let bytes = rows
                            .get(&id.to_string())
                            .ok_or(signal::Error::MissingPreKey)?;
                        let pair = decode_key(id, bytes).map_err(storage)?;
                        list.push(pre_key_node(pair.public.expose(), id));
                    }
                }
                let node = Node {
                    tag: "iq".into(),
                    attrs: vec![
                        ("xmlns".into(), "encrypt".into()),
                        ("type".into(), "set".into()),
                        ("to".into(), crate::jid::S_WHATSAPP_NET.into()),
                    ],
                    content: Some(Content::Nodes(vec![
                        data(
                            "registration",
                            u32::from(self.registration).to_be_bytes().to_vec(),
                        ),
                        data("type", vec![5]),
                        data("identity", self.identity.to_vec()),
                        child("list", Content::Nodes(list)),
                        xmpp_signed_pre_key(&crate::signed_keys::active(tx, &self.identity)?)
                            .map_err(storage)?,
                    ])),
                };
                tx.put("meta", CURSORS, &plan.counters.encode())?;
                Ok(Prepared {
                    node,
                    first: plan.first,
                    count,
                    counters: plan.counters,
                })
            })
            .map_err(Into::into)
    }
}
fn decode_key(id: u32, bytes: &[u8]) -> Result<KeyPair> {
    let record = codec::decode_pre_key(bytes).map_err(|_| Error::InvalidKey)?;
    if record.id != id {
        return Err(Error::InvalidKey);
    }
    let pair = KeyPair {
        public: Bytes::new(record.key_pair.public.to_vec()),
        private: Bytes::new(record.key_pair.private.to_vec()),
    };
    pair.validate().map_err(|_| Error::InvalidKey)?;
    Ok(pair)
}
pub fn count_query() -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![
            ("xmlns".into(), "encrypt".into()),
            ("type".into(), "get".into()),
            ("to".into(), crate::jid::S_WHATSAPP_NET.into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: "count".into(),
            attrs: vec![],
            content: None,
        }])),
    }
}
pub fn passive_query(active: bool) -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![
            ("to".into(), crate::jid::S_WHATSAPP_NET.into()),
            ("xmlns".into(), "passive".into()),
            ("type".into(), "set".into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: if active { "active" } else { "passive" }.into(),
            attrs: vec![],
            content: None,
        }])),
    }
}
pub fn digest_query() -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![
            ("to".into(), crate::jid::S_WHATSAPP_NET.into()),
            ("type".into(), "get".into()),
            ("xmlns".into(), "encrypt".into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: "digest".into(),
            attrs: vec![],
            content: None,
        }])),
    }
}
fn unique_child<'a>(node: &'a Node, tag: &str) -> Result<Option<&'a Node>> {
    let Some(Content::Nodes(children)) = &node.content else {
        return Ok(None);
    };
    let mut found = children.iter().filter(|child| child.tag == tag);
    let first = found.next();
    if found.next().is_some() {
        return Err(Error::InvalidResponse);
    }
    Ok(first)
}
pub fn parse_count(node: &Node) -> Result<u32> {
    let count = unique_child(node, "count")?.ok_or(Error::InvalidResponse)?;
    let mut attrs = count.attrs.iter().filter(|(k, _)| k == "value");
    let value = attrs
        .next()
        .ok_or(Error::InvalidResponse)?
        .1
        .parse::<u32>()
        .map_err(|_| Error::InvalidResponse)?;
    if attrs.next().is_some() {
        return Err(Error::InvalidResponse);
    }
    Ok(value)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadDecision {
    pub requested_count: u32,
    pub should_upload: bool,
}
pub fn upload_decision(server_count: u32, current_id: u32, current_exists: bool) -> UploadDecision {
    let requested_count = if server_count == 0 {
        INITIAL_PREKEY_COUNT
    } else {
        MIN_PREKEY_COUNT
    };
    UploadDecision {
        requested_count,
        should_upload: server_count <= requested_count || (!current_exists && current_id > 0),
    }
}
/// Endpoint adapters must surface stanza errors, not return them as successful IQs.
pub trait Query: Send + Sync + 'static {
    fn query(&self, node: Node) -> impl Future<Output = socket::Result<Arc<Node>>> + Send;
}
impl Query for socket::Connection {
    fn query(&self, node: Node) -> impl Future<Output = socket::Result<Arc<Node>>> + Send {
        socket::Connection::query(self, node)
    }
}
#[derive(Debug, Clone)]
pub struct UploadPolicy {
    pub max_attempts: u32,
    pub timeout: Duration,
    pub first_backoff: Duration,
    pub max_backoff: Duration,
}
impl Default for UploadPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            timeout: Duration::from_secs(30),
            first_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
        }
    }
}
impl UploadPolicy {
    fn validate(&self) -> Result<()> {
        if self.max_attempts == 0
            || self.max_attempts > 4
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(86_400)
            || self.max_backoff > Duration::from_secs(86_400)
            || self.max_backoff.is_zero()
            || self.first_backoff.is_zero()
            || self.first_backoff > self.max_backoff
        {
            Err(Error::InvalidPolicy)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone)]
pub struct UploadReport {
    pub first: u32,
    pub count: u32,
    pub counters: Counters,
    pub attempts: u32,
}
type Flight = Shared<BoxFuture<'static, Result<UploadReport>>>;
struct Gate {
    next: u64,
    flight: Option<(u64, Flight)>,
}
struct Context<S: Store, Q: Query> {
    manager: Arc<Manager<S>>,
    endpoint: Q,
    policy: UploadPolicy,
}
pub struct Uploader<S: Store, Q: Query> {
    context: Arc<Context<S, Q>>,
    gate: Arc<Mutex<Gate>>,
}
impl<S: Store, Q: Query> Clone for Uploader<S, Q> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            gate: self.gate.clone(),
        }
    }
}
impl<S: Store + Send + Sync + 'static, Q: Query> Uploader<S, Q> {
    pub fn new(manager: Arc<Manager<S>>, endpoint: Q, policy: UploadPolicy) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            context: Arc::new(Context {
                manager,
                endpoint,
                policy,
            }),
            gate: Arc::new(Mutex::new(Gate {
                next: 0,
                flight: None,
            })),
        })
    }
    pub async fn upload(&self, count: u32) -> Result<UploadReport> {
        if count == 0 || count > MAX_BATCH {
            return Err(Error::InvalidCount);
        }
        let flight = {
            let mut gate = self.gate.lock().await;
            if let Some((_, flight)) = &gate.flight {
                flight.clone()
            } else {
                let id = gate.next;
                gate.next = gate.next.checked_add(1).ok_or(Error::Exhausted)?;
                let context = self.context.clone();
                let slot = self.gate.clone();
                let deadline = Instant::now() + context.policy.timeout;
                let task = tokio::spawn(async move {
                    let result = match tokio::time::timeout_at(
                        deadline,
                        AssertUnwindSafe(perform_upload(context, count)).catch_unwind(),
                    )
                    .await
                    {
                        Err(_) => Err(Error::Timeout),
                        Ok(Err(_)) => Err(Error::Worker),
                        Ok(Ok(result)) => result,
                    };
                    let mut gate = slot.lock().await;
                    if gate
                        .flight
                        .as_ref()
                        .is_some_and(|(current, _)| *current == id)
                    {
                        gate.flight = None;
                    }
                    result
                });
                let flight = async move { task.await.map_err(|_| Error::Worker)? }
                    .boxed()
                    .shared();
                gate.flight = Some((id, flight.clone()));
                flight
            }
        };
        flight.await
    }
    /// Process the prekey/active/digest part of an authenticated success stanza.
    /// Auxiliary failures are reported separately, matching the legacy open path.
    pub async fn initialize(&self, success: &Node) -> Result<InitializationReport> {
        if success.tag != "success" {
            return Err(Error::InvalidResponse);
        }
        let lid = success
            .attrs
            .iter()
            .find(|(k, _)| k == "lid")
            .map(|(_, v)| v.clone());
        let prekeys = async {
            let count = parse_count(self.context.endpoint.query(count_query()).await?.as_ref())?;
            let manager = self.context.manager.clone();
            let (id, exists) = tokio::task::spawn_blocking(move || manager.current_pre_key())
                .await
                .map_err(|_| Error::Worker)??;
            let decision = upload_decision(count, id, exists);
            if decision.should_upload {
                self.upload(decision.requested_count).await.map(Some)
            } else {
                Ok(None)
            }
        }
        .await;
        let active = self
            .context
            .endpoint
            .query(passive_query(true))
            .await
            .map(|_| ())
            .map_err(Into::into);
        let digest = if active.is_ok() {
            Some(
                async {
                    let response = self.context.endpoint.query(digest_query()).await?;
                    if unique_child(&response, "digest")?.is_none() {
                        self.upload(MIN_PREKEY_COUNT).await?;
                        return Err(Error::MissingDigest);
                    }
                    Ok(())
                }
                .await,
            )
        } else {
            None
        };
        Ok(InitializationReport {
            lid,
            prekeys,
            active,
            digest,
        })
    }
}
async fn perform_upload<S: Store + Send + Sync + 'static, Q: Query>(
    context: Arc<Context<S, Q>>,
    count: u32,
) -> Result<UploadReport> {
    let _publication = context.manager.publication.lock().await;
    for attempt in 1..=context.policy.max_attempts {
        let manager = context.manager.clone();
        let prepared = tokio::task::spawn_blocking(move || manager.prepare(count))
            .await
            .map_err(|_| Error::Worker)??;
        match context.endpoint.query(prepared.node).await {
            Ok(_) => {
                return Ok(UploadReport {
                    first: prepared.first,
                    count,
                    counters: prepared.counters,
                    attempts: attempt,
                });
            }
            Err(error) if attempt == context.policy.max_attempts => {
                return Err(Error::Network(error));
            }
            Err(_) => {
                let delay = context
                    .policy
                    .first_backoff
                    .saturating_mul(1 << (attempt - 1))
                    .min(context.policy.max_backoff);
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(Error::Worker)
}
#[derive(Debug, Clone)]
pub struct InitializationReport {
    pub lid: Option<String>,
    pub prekeys: Result<Option<UploadReport>>,
    pub active: Result<()>,
    pub digest: Option<Result<()>>,
}
