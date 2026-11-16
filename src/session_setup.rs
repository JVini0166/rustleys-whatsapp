//! Device discovery and outgoing Signal preparation (Baileys MIT source port).
//! Single-owner async facade; persistent/cryptographic work runs off the executor.
use crate::{
    auth::Credentials,
    binary::{Content, Node},
    jid,
    lid_mapping::{Clock, LidMappingStore, Mapping, SystemClock},
    prekeys::Query as Endpoint,
    signal::{self, PreKeyBundle, PublicSignedPreKey, Repository, Store},
    usync,
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Debug, Clone)]
pub enum Error {
    InvalidAddress,
    InvalidBundle,
    InvalidResponse,
    DuplicateRecipient,
    MissingRecipient,
    UnexpectedRecipient,
    Limit,
    InvalidConfig,
    Worker,
    Timeout,
    Poisoned,
    RevisionExhausted,
    Server(Option<u16>),
    Signal(Arc<signal::Error>),
    Usync(usync::Error),
    Network(crate::socket::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session setup: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<signal::Error> for Error {
    fn from(e: signal::Error) -> Self {
        Self::Signal(Arc::new(e))
    }
}
impl From<usync::Error> for Error {
    fn from(e: usync::Error) -> Self {
        Self::Usync(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn attr<'a>(n: &'a Node, k: &str) -> Option<&'a str> {
    n.attrs
        .iter()
        .rev()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
}
fn children(n: &Node) -> &[Node] {
    match &n.content {
        Some(Content::Nodes(c)) => c,
        _ => &[],
    }
}
fn child<'a>(n: &'a Node, k: &str) -> Option<&'a Node> {
    children(n).iter().find(|n| n.tag == k)
}
fn bytes<'a>(n: &'a Node, k: &str) -> Option<&'a [u8]> {
    match &child(n, k)?.content {
        Some(Content::Bytes(b)) => Some(b),
        _ => None,
    }
}
fn uint(n: &Node, k: &str, len: usize) -> Option<u32> {
    let b = bytes(n, k)?;
    if b.len() != len {
        return None;
    }
    Some(b.iter().fold(0, |v, b| v << 8 | u32::from(*b)))
}
fn pubkey(bytes: &[u8]) -> Result<[u8; 32]> {
    match bytes {
        b if b.len() == 32 => b.try_into().map_err(|_| Error::InvalidBundle),
        [5, rest @ ..] if rest.len() == 32 => rest.try_into().map_err(|_| Error::InvalidBundle),
        _ => Err(Error::InvalidBundle),
    }
}
fn error_free(n: &Node) -> Result<()> {
    if let Some(e) = child(n, "error") {
        return Err(Error::Server(attr(e, "code").and_then(|v| v.parse().ok())));
    }
    Ok(())
}
fn bundle(n: &Node, registration: &Node) -> Result<PreKeyBundle> {
    let skey = child(n, "skey").ok_or(Error::InvalidBundle)?;
    Ok(PreKeyBundle {
        registration_id: uint(registration, "registration", 4).ok_or(Error::InvalidBundle)?,
        identity: pubkey(bytes(n, "identity").ok_or(Error::InvalidBundle)?)?,
        signed_pre_key: PublicSignedPreKey {
            id: uint(skey, "id", 3).ok_or(Error::InvalidBundle)?,
            public: pubkey(bytes(skey, "value").ok_or(Error::InvalidBundle)?)?,
            signature: bytes(skey, "signature")
                .ok_or(Error::InvalidBundle)?
                .try_into()
                .map_err(|_| Error::InvalidBundle)?,
        },
        one_time_pre_key: child(n, "key")
            .map(|key| {
                Ok::<_, Error>((
                    uint(key, "id", 3).ok_or(Error::InvalidBundle)?,
                    pubkey(bytes(key, "value").ok_or(Error::InvalidBundle)?)?,
                ))
            })
            .transpose()?,
    })
}
/// Parse/preflight every server error before returning any bundle. No storage is
/// changed. Correlation with a key request is enforced by Client::assert_sessions.
pub fn parse_bundles(n: &Node) -> Result<Vec<(String, PreKeyBundle)>> {
    usync::check_node(n)?;
    error_free(n)?;
    let users = child(n, "list")
        .map(children)
        .unwrap_or_default()
        .iter()
        .filter(|n| n.tag == "user")
        .collect::<Vec<_>>();
    if users.len() > 1024 {
        return Err(Error::Limit);
    }
    for user in &users {
        error_free(user)?;
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for user in users {
        let id = attr(user, "jid").ok_or(Error::InvalidAddress)?;
        let address = signal::protocol_address(id).map_err(|_| Error::InvalidAddress)?;
        if !seen.insert(address) {
            return Err(Error::DuplicateRecipient);
        }
        result.push((id.into(), bundle(user, user)?));
    }
    Ok(result)
}
/// Retry receipts put registration on the receipt, not inside keys. The source
/// treats an absent/invalid key envelope as null; strict lengths remain explicit.
pub fn bundle_from_retry(receipt: &Node) -> Result<Option<PreKeyBundle>> {
    usync::check_node(receipt)?;
    let Some(keys) = child(receipt, "keys") else {
        return Ok(None);
    };
    if bytes(keys, "type") != Some(&[5][..]) {
        return Ok(None);
    }
    // The retry helper in the original requires untagged 32-byte public keys.
    if bytes(keys, "identity").is_none_or(|b| b.len() != 32)
        || child(keys, "skey")
            .and_then(|n| bytes(n, "value"))
            .is_none_or(|b| b.len() != 32)
        || child(keys, "key").is_some_and(|n| bytes(n, "value").is_none_or(|b| b.len() != 32))
    {
        return Ok(None);
    }
    Ok(bundle(keys, receipt).ok())
}
pub fn key_query(jids: &[String], force: bool) -> Result<Node> {
    if jids.len() > 1024 {
        return Err(Error::Limit);
    }
    let mut users = Vec::new();
    for id in jids {
        signal::protocol_address(id).map_err(|_| Error::InvalidAddress)?;
        let mut attrs = vec![("jid".into(), id.clone())];
        if force {
            attrs.push(("reason".into(), "identity".into()));
        }
        users.push(Node {
            tag: "user".into(),
            attrs,
            content: None,
        });
    }
    Ok(Node {
        tag: "iq".into(),
        attrs: vec![
            ("xmlns".into(), "encrypt".into()),
            ("type".into(), "get".into()),
            ("to".into(), jid::S_WHATSAPP_NET.into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: "key".into(),
            attrs: vec![],
            content: Some(Content::Nodes(users)),
        }])),
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub user: String,
    pub device: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub jid: String,
}
fn integer(v: Option<&serde_json::Value>) -> Option<u32> {
    v?.as_u64().and_then(|v| v.try_into().ok())
}
pub fn extract_devices(
    rows: &[usync::Row],
    my_jid: &str,
    my_lid: Option<&str>,
    ignore_zero: bool,
) -> Result<Vec<Device>> {
    if rows.len() > 8192 {
        return Err(Error::Limit);
    }
    let me = jid::jid_decode(my_jid).map_err(|_| Error::InvalidAddress)?;
    let my_lid_user = my_lid.and_then(|j| jid::jid_decode(j).ok()).map(|j| j.user);
    let mut result = Vec::new();
    for row in rows {
        let decoded = jid::jid_decode(&row.id).map_err(|_| Error::InvalidAddress)?;
        let Some(list) = row
            .data
            .get("devices")
            .and_then(|v| v.get("deviceList"))
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        if list.len() > 1024 {
            return Err(Error::Limit);
        }
        for item in list {
            let Some(id) = integer(item.get("id")) else {
                return Err(Error::InvalidResponse);
            };
            if ignore_zero && id == 0 {
                continue;
            }
            if (me.user == decoded.user || my_lid_user == Some(decoded.user))
                && me.device == Some(id)
            {
                continue;
            }
            if id != 0 && integer(item.get("keyIndex")).filter(|v| *v != 0).is_none() {
                continue;
            }
            let domain = if item.get("isHosted").and_then(|v| v.as_bool()) == Some(true) {
                if decoded.domain_type == 1 || decoded.domain_type == 129 {
                    129
                } else {
                    128
                }
            } else {
                decoded.domain_type
            };
            let server = jid::get_server_from_domain_type(decoded.server, Some(domain));
            result.push(Device {
                user: decoded.user.into(),
                device: id,
                domain_type: Some(domain),
                server: Some(server.into()),
                jid: jid::jid_encode(decoded.user, server, Some(id), None),
            });
            if result.len() > 8192 {
                return Err(Error::Limit);
            }
        }
    }
    Ok(result)
}
#[derive(Clone)]
pub struct Options {
    pub own_jid: String,
    pub own_lid: Option<String>,
    pub cache_capacity: NonZeroUsize,
    pub cache_ttl: Duration,
    pub timeout: Duration,
}
impl Options {
    pub fn new(own_jid: impl Into<String>, own_lid: Option<String>) -> Self {
        Self {
            own_jid: own_jid.into(),
            own_lid,
            cache_capacity: NonZeroUsize::new(10000).unwrap(),
            cache_ttl: Duration::from_secs(300),
            timeout: Duration::from_secs(180),
        }
    }
}
#[derive(Debug, Clone)]
pub struct DeviceReport {
    pub devices: Vec<Device>,
    pub session_refresh_error: Option<Error>,
    pub device_list_error: Option<Error>,
}
#[derive(Clone)]
struct Shared<Q>(Arc<Q>);
impl<Q: Endpoint> Endpoint for Shared<Q> {
    async fn query(&self, n: Node) -> crate::socket::Result<Arc<Node>> {
        self.0.query(n).await
    }
}
struct Entry {
    devices: Vec<Device>,
    expires: Instant,
}
struct Context<S: Store, Q> {
    repo: Arc<Repository<S>>,
    mappings: Arc<LidMappingStore<S>>,
    endpoint: Arc<Q>,
    usync: usync::Client<Shared<Q>>,
    options: Options,
    clock: Arc<dyn Clock>,
    cache: Mutex<LruCache<String, Entry>>,
    owner: tokio::sync::Mutex<()>,
    cache_revision: AtomicU64,
}
pub struct Client<S: Store, Q> {
    context: Arc<Context<S, Q>>,
}
impl<S: Store, Q> Clone for Client<S, Q> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}
impl<S: Store, Q> std::fmt::Debug for Client<S, Q> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSetupClient([redacted])")
    }
}
fn namespace(id: &str) -> Result<String> {
    let d = jid::jid_decode(id).map_err(|_| Error::InvalidAddress)?;
    let domain = if matches!(d.domain_type, 1 | 129) {
        "lid"
    } else {
        "pn"
    };
    Ok(format!("{domain}:{}", d.user))
}
fn validate_jids(jids: &[String]) -> Result<()> {
    if jids.len() > 1024 {
        return Err(Error::Limit);
    }
    for id in jids {
        if id.len() > 1024 {
            return Err(Error::Limit);
        }
        signal::protocol_address(id).map_err(|_| Error::InvalidAddress)?;
    }
    Ok(())
}
async fn worker<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| Error::Worker)?
}
impl<S: Store + Clone + Send + Sync + 'static, Q: Endpoint> Client<S, Q> {
    pub fn new(creds: &Credentials, store: S, endpoint: Q, options: Options) -> Result<Self> {
        Self::with_clock(creds, store, endpoint, options, Arc::new(SystemClock))
    }
    pub fn with_clock(
        creds: &Credentials,
        store: S,
        endpoint: Q,
        options: Options,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        validate_jids(std::slice::from_ref(&options.own_jid))?;
        if let Some(lid) = &options.own_lid {
            validate_jids(std::slice::from_ref(lid))?;
        }
        if options.cache_ttl.is_zero()
            || options.cache_ttl > Duration::from_secs(86400)
            || options.timeout.is_zero()
            || options.timeout > Duration::from_secs(300)
        {
            return Err(Error::InvalidConfig);
        }
        let repo = Arc::new(Repository::new(creds, store.clone())?);
        let mappings = Arc::new(LidMappingStore::new(store));
        let endpoint = Arc::new(endpoint);
        let usync = usync::Client::new(Shared(endpoint.clone()))?;
        let capacity = options.cache_capacity;
        Ok(Self {
            context: Arc::new(Context {
                repo,
                mappings,
                endpoint,
                usync,
                options,
                clock,
                cache: Mutex::new(LruCache::new(capacity)),
                owner: tokio::sync::Mutex::new(()),
                cache_revision: AtomicU64::new(0),
            }),
        })
    }
    pub fn repository(&self) -> Arc<Repository<S>> {
        self.context.repo.clone()
    }
    pub fn mappings(&self) -> Arc<LidMappingStore<S>> {
        self.context.mappings.clone()
    }
    pub fn invalidate_devices(&self, jid: &str) -> Result<()> {
        let mut cache = self.context.cache.lock().map_err(|_| Error::Poisoned)?;
        self.context
            .cache_revision
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| Error::RevisionExhausted)?;
        cache.pop(&namespace(jid)?);
        Ok(())
    }
    pub async fn assert_sessions(&self, jids: &[String], force: bool) -> Result<bool> {
        validate_jids(jids)?;
        let jids = jids.to_vec();
        let c = self.context.clone();
        let timeout = c.options.timeout;
        tokio::spawn(async move {
            use futures_util::FutureExt;
            tokio::time::timeout(
                timeout,
                std::panic::AssertUnwindSafe(async move {
                    let _owner = c.owner.lock().await;
                    assert_inner(&c, jids, force).await
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
    pub async fn get_devices(
        &self,
        jids: &[String],
        use_cache: bool,
        ignore_zero: bool,
    ) -> Result<DeviceReport> {
        validate_jids(jids)?;
        let jids = jids.to_vec();
        let c = self.context.clone();
        let timeout = c.options.timeout;
        tokio::spawn(async move {
            use futures_util::FutureExt;
            tokio::time::timeout(
                timeout,
                std::panic::AssertUnwindSafe(async move {
                    let _owner = c.owner.lock().await;
                    devices_inner(&c, jids, use_cache, ignore_zero).await
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
fn mapping_migrations(pairs: &[Mapping], devices: &[Device]) -> Result<Vec<(String, String)>> {
    let mut forward = HashMap::new();
    let mut reverse = HashMap::new();
    let mut out = Vec::new();
    for pair in pairs {
        let pn = jid::jid_decode(&pair.pn).map_err(|_| Error::InvalidResponse)?;
        let lid = jid::jid_decode(&pair.lid).map_err(|_| Error::InvalidResponse)?;
        if !matches!(pn.server, "s.whatsapp.net" | "hosted")
            || !matches!(lid.server, "lid" | "hosted.lid")
            || pn.user.is_empty()
            || lid.user.is_empty()
        {
            return Err(Error::InvalidResponse);
        }
        if forward
            .insert(pn.user, lid.user)
            .is_some_and(|v| v != lid.user)
            || reverse
                .insert(lid.user, pn.user)
                .is_some_and(|v| v != pn.user)
        {
            return Err(Error::InvalidResponse);
        }
        out.push((pair.pn.clone(), pair.lid.clone()));
        for d in devices.iter().filter(|d| {
            d.user == pn.user
                && d.domain_type
                    .is_some_and(|domain| !matches!(domain, 1 | 129))
        }) {
            let server = d.server.as_deref().ok_or(Error::InvalidResponse)?;
            out.push((
                jid::jid_encode(pn.user, server, Some(d.device), None),
                jid::jid_encode(
                    lid.user,
                    if server == "hosted" {
                        "hosted.lid"
                    } else {
                        "lid"
                    },
                    Some(d.device),
                    None,
                ),
            ));
        }
    }
    let mut seen = HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    Ok(out)
}
async fn resolve<S: Store + Clone + Send + Sync + 'static, Q: Endpoint>(
    c: &Arc<Context<S, Q>>,
    pns: Vec<String>,
) -> Result<Vec<Mapping>> {
    if pns.is_empty() {
        return Ok(vec![]);
    }
    let store = c.mappings.clone();
    let input = pns.clone();
    let known = worker(move || {
        store
            .get_lids_for_pns(&input)
            .map_err(|e| Error::Signal(e.0))
    })
    .await?;
    let found: HashSet<_> = known.iter().map(|m| m.pn.as_str()).collect();
    let mut seen = HashSet::new();
    let missing: Vec<_> = pns
        .iter()
        .filter(|id| !found.contains(id.as_str()))
        .map(|id| {
            jid::jid_decode(id)
                .map(|d| format!("{}@s.whatsapp.net", d.user))
                .map_err(|_| Error::InvalidAddress)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect();
    if !missing.is_empty() {
        let requested: HashSet<_> = missing.iter().cloned().collect();
        let pairs = c.usync.pn_from_lid(&missing).await?;
        let pairs: Vec<_> = pairs
            .into_iter()
            .filter(|p| requested.contains(&p.pn))
            .collect();
        let repo = c.repo.clone();
        worker(move || {
            let migrations = mapping_migrations(&pairs, &[])?;
            repo.migrate_sessions(&migrations)?;
            Ok(())
        })
        .await?;
    }
    let store = c.mappings.clone();
    worker(move || store.get_lids_for_pns(&pns).map_err(|e| Error::Signal(e.0))).await
}
async fn assert_inner<S: Store + Clone + Send + Sync + 'static, Q: Endpoint>(
    c: &Arc<Context<S, Q>>,
    jids: Vec<String>,
    force: bool,
) -> Result<bool> {
    let repo = c.repo.clone();
    let requiring = worker(move || {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for id in jids {
            if seen.insert(id.clone()) && (force || !repo.validate_session(&id)?.exists) {
                out.push(id);
            }
        }
        Ok(out)
    })
    .await?;
    if requiring.is_empty() {
        return Ok(false);
    }
    let pns = requiring
        .iter()
        .filter(|id| jid::is_pn_user(Some(id)) || jid::is_hosted_pn_user(Some(id)))
        .cloned()
        .collect::<Vec<_>>();
    let pairs = resolve(c, pns.clone()).await?;
    let mut wire: Vec<_> = requiring
        .iter()
        .filter(|id| jid::is_lid_user(Some(id)) || jid::is_hosted_lid_user(Some(id)))
        .cloned()
        .collect();
    wire.extend(pairs.iter().map(|p| p.lid.clone()));
    // The upstream comment promises PN fallback, but its code silently drops
    // unmapped PNs. Preserve the recipient rather than issuing an empty key IQ.
    wire.extend(
        pns.into_iter()
            .filter(|pn| !pairs.iter().any(|m| m.pn == *pn)),
    );
    let mut addresses = HashSet::new();
    let mut unique_wire = Vec::new();
    for id in wire {
        if addresses.insert(signal::protocol_address(&id)?) {
            unique_wire.push(id);
        }
    }
    let wire = unique_wire;
    if wire.is_empty() {
        return Err(Error::MissingRecipient);
    }
    let response = c
        .endpoint
        .query(key_query(&wire, force)?)
        .await
        .map_err(Error::Network)?;
    let bundles = parse_bundles(&response)?;
    let wanted: HashSet<_> = wire
        .iter()
        .map(|id| signal::protocol_address(id))
        .collect::<signal::Result<_>>()?;
    let received: HashSet<_> = bundles
        .iter()
        .map(|(id, _)| signal::protocol_address(id))
        .collect::<signal::Result<_>>()?;
    if received.iter().any(|id| !wanted.contains(id)) {
        return Err(Error::UnexpectedRecipient);
    }
    if wanted != received {
        return Err(Error::MissingRecipient);
    }
    let repo = c.repo.clone();
    worker(move || repo.inject_sessions(&bundles).map_err(Into::into)).await?;
    Ok(true)
}
async fn devices_inner<S: Store + Clone + Send + Sync + 'static, Q: Endpoint>(
    c: &Arc<Context<S, Q>>,
    jids: Vec<String>,
    use_cache: bool,
    ignore_zero: bool,
) -> Result<DeviceReport> {
    let mut out = DeviceReport {
        devices: vec![],
        session_refresh_error: None,
        device_list_error: None,
    };
    let mut fetch = Vec::new();
    for id in jids {
        let d = jid::jid_decode(&id).map_err(|_| Error::InvalidAddress)?;
        if let Some(device) = d.device {
            out.devices.push(Device {
                user: d.user.into(),
                device,
                domain_type: None,
                server: None,
                jid: id,
            });
            continue;
        }
        let cached = if use_cache {
            let mut cache = c.cache.lock().map_err(|_| Error::Poisoned)?;
            let key = namespace(&id)?;
            if cache.peek(&key).is_some_and(|e| e.expires <= c.clock.now()) {
                cache.pop(&key);
            }
            cache.get(&key).map(|e| e.devices.clone())
        } else {
            None
        };
        if let Some(devices) = cached {
            out.devices.extend(
                devices
                    .into_iter()
                    .filter(|d| !ignore_zero || d.device != 0),
            );
        } else {
            fetch.push(jid::jid_normalized_user(Some(&id)));
        }
    }
    if fetch.is_empty() {
        return Ok(out);
    }
    let mut query = usync::Query::default()
        .with_context("message")
        .with_protocol(usync::Builtin::Devices)
        .with_protocol(usync::Builtin::Lid);
    for id in &fetch {
        query.users.push(usync::User::default().with_id(id));
    }
    let revision = c.cache_revision.load(Ordering::Acquire);
    let Some(result) = c.usync.execute(&query).await? else {
        return Ok(out);
    };
    let requested: HashSet<_> = fetch.iter().map(String::as_str).collect();
    let mut result = result;
    result.list.retain(|r| requested.contains(r.id.as_str()));
    let devices = extract_devices(
        &result.list,
        &c.options.own_jid,
        c.options.own_lid.as_deref(),
        false,
    )?;
    let pairs: Vec<_> = result
        .list
        .iter()
        .filter(|r| jid::is_pn_user(Some(&r.id)) || jid::is_hosted_pn_user(Some(&r.id)))
        .filter_map(|r| {
            r.data
                .get("lid")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|lid| Mapping {
                    pn: r.id.clone(),
                    lid: lid.into(),
                })
        })
        .collect();
    if !pairs.is_empty() {
        let repo = c.repo.clone();
        let saving = pairs.clone();
        let migrating_devices = devices.clone();
        worker(move || {
            repo.migrate_sessions(&mapping_migrations(&saving, &migrating_devices)?)?;
            Ok(())
        })
        .await?;
        out.session_refresh_error =
            assert_inner(c, pairs.into_iter().map(|p| p.lid).collect(), true)
                .await
                .err();
    }
    // Cache the full zero-device policy-independent list. Filter only on output.
    let mut grouped: Vec<(String, Vec<Device>)> = Vec::new();
    for row in &result.list {
        let key = namespace(&row.id)?;
        let d = jid::jid_decode(&row.id).map_err(|_| Error::InvalidAddress)?;
        let ds: Vec<_> = devices
            .iter()
            .filter(|item| {
                item.user == d.user
                    && item.domain_type.is_some_and(|domain| {
                        matches!(domain, 1 | 129) == matches!(d.domain_type, 1 | 129)
                    })
            })
            .cloned()
            .collect();
        if !ds.is_empty() {
            grouped.push((key, ds));
        }
    }
    out.devices.extend(
        devices
            .into_iter()
            .filter(|d| !ignore_zero || d.device != 0),
    );
    let expires = c
        .clock
        .now()
        .checked_add(c.options.cache_ttl)
        .ok_or(Error::InvalidConfig)?;
    {
        let mut cache = c.cache.lock().map_err(|_| Error::Poisoned)?;
        if c.cache_revision.load(Ordering::Acquire) != revision {
            return Ok(out);
        }
        for (key, devices) in &grouped {
            cache.put(
                key.clone(),
                Entry {
                    devices: devices.clone(),
                    expires,
                },
            );
        }
    }
    let repo = c.repo.clone();
    let updates: Vec<_> = grouped
        .into_iter()
        .filter_map(|(key, devices)| {
            let first = devices.first()?;
            let server = if key.starts_with("lid:") {
                "lid"
            } else {
                "s.whatsapp.net"
            };
            Some((
                jid::jid_encode(&first.user, server, None, None),
                devices.into_iter().map(|d| d.device).collect::<Vec<_>>(),
            ))
        })
        .collect();
    out.device_list_error = worker(move || {
        for (id, devices) in updates {
            repo.set_discovery_device_list(&id, &devices)?;
        }
        Ok(())
    })
    .await
    .err();
    Ok(out)
}
