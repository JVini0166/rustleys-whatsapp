//! PN/LID mappings with atomic bijection updates and revision-aware bounded cache.
//! Resolver calls are synchronous and must run off an async network executor.
use crate::{
    jid,
    signal::{Error, Result, Store, Transaction},
};
use lru::LruCache;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
const REVISION: &str = "lid-mapping-revision";
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mapping {
    pub pn: String,
    pub lid: String,
}
#[derive(Debug, Clone)]
pub struct LookupError(pub Arc<Error>);
impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for LookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl From<Error> for LookupError {
    fn from(e: Error) -> Self {
        Self(Arc::new(e))
    }
}
pub type LookupResult<T> = std::result::Result<T, LookupError>;
/// The resolver must return authenticated USync mappings for the requested
/// normalized PNs. It must not recursively resolve the same in-flight batch.
pub trait Resolver: Send + Sync {
    fn resolve(&self, pns: &[String]) -> LookupResult<Vec<Mapping>>;
}
impl<F> Resolver for F
where
    F: Fn(&[String]) -> LookupResult<Vec<Mapping>> + Send + Sync,
{
    fn resolve(&self, pns: &[String]) -> LookupResult<Vec<Mapping>> {
        self(pns)
    }
}
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
#[derive(Debug, Clone)]
pub struct CacheOptions {
    pub capacity: NonZeroUsize,
    pub ttl: Duration,
}
impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            capacity: NonZeroUsize::new(10000).unwrap(),
            ttl: Duration::from_secs(3 * 24 * 60 * 60),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Direction {
    Forward,
    Reverse,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    direction: Direction,
    user: String,
}
struct CacheEntry {
    value: String,
    expires: Option<Instant>,
}
struct Cache {
    revision: Option<u64>,
    values: LruCache<CacheKey, CacheEntry>,
}
type Resolved = HashMap<String, String>;
#[derive(PartialEq, Eq, Hash, Clone)]
struct FlightKey(Vec<String>);
struct Flight {
    result: Mutex<Option<LookupResult<()>>>,
    ready: Condvar,
}
struct State {
    coalesced: AtomicU64,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<FlightKey, Arc<Flight>>>,
}
pub struct LidMappingStore<S: Store> {
    store: S,
    state: Arc<State>,
    resolver: Option<Arc<dyn Resolver>>,
    options: CacheOptions,
    clock: Arc<dyn Clock>,
}
impl<S: Store + Clone> Clone for LidMappingStore<S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            state: self.state.clone(),
            resolver: self.resolver.clone(),
            options: self.options.clone(),
            clock: self.clock.clone(),
        }
    }
}
impl<S: Store> std::fmt::Debug for LidMappingStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LidMappingStore([redacted])")
    }
}
fn text(tx: &mut dyn Transaction, key: &str) -> Result<Option<String>> {
    tx.get("lid-mapping", key)?
        .map(|bytes| String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidMapping))
        .transpose()
}
fn revision(tx: &mut dyn Transaction) -> Result<u64> {
    match tx.get("meta", REVISION)? {
        None => Ok(0),
        Some(bytes) => Ok(u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidMapping)?,
        )),
    }
}
pub(crate) fn decode(j: &str, phone: bool) -> Option<jid::Jid<'_>> {
    let d = jid::jid_decode(j).ok()?;
    if d.user.is_empty()
        || d.user.contains('.')
        || !if phone {
            matches!(d.server, "s.whatsapp.net" | "hosted")
        } else {
            matches!(d.server, "lid" | "hosted.lid")
        }
    {
        return None;
    }
    Some(d)
}
fn normalize(pair: &Mapping) -> Option<(String, String)> {
    if let (Some(pn), Some(lid)) = (decode(&pair.pn, true), decode(&pair.lid, false)) {
        Some((pn.user.into(), lid.user.into()))
    } else if let (Some(pn), Some(lid)) = (decode(&pair.lid, true), decode(&pair.pn, false)) {
        Some((pn.user.into(), lid.user.into()))
    } else {
        None
    }
}
/// Internal transaction primitive shared with repository migration. All writes
/// through this mapping API update the revision; custom backends must preserve it.
pub(crate) fn write_pairs(
    tx: &mut dyn Transaction,
    pairs: &[Mapping],
    only_missing: bool,
) -> Result<usize> {
    let mut changed = 0;
    for pair in pairs {
        let Some((pn, lid)) = normalize(pair) else {
            continue;
        };
        let reverse = format!("{lid}_reverse");
        let old_lid = text(tx, &pn)?.filter(|value| !value.is_empty());
        let old_pn = text(tx, &reverse)?.filter(|value| !value.is_empty());
        if old_lid.as_deref() == Some(&lid) && old_pn.as_deref() == Some(&pn) {
            continue;
        }
        if only_missing && (old_lid.is_some() || old_pn.is_some()) {
            continue;
        }
        if let Some(old) = old_lid
            && old != lid
        {
            let old_reverse = format!("{old}_reverse");
            if text(tx, &old_reverse)?.as_deref() == Some(&pn) {
                tx.remove("lid-mapping", &old_reverse)?;
            }
        }
        if let Some(old) = old_pn
            && old != pn
            && text(tx, &old)?.as_deref() == Some(&lid)
        {
            tx.remove("lid-mapping", &old)?;
        }
        tx.put("lid-mapping", &pn, lid.as_bytes())?;
        tx.put("lid-mapping", &reverse, pn.as_bytes())?;
        changed += 1;
    }
    if changed > 0 {
        let next = revision(tx)?
            .checked_add(1)
            .ok_or(crate::signal::Error::Protocol(
                wacore_libsignal::engine::Error::CounterExhausted,
            ))?;
        tx.put("meta", REVISION, &next.to_be_bytes())?;
    }
    Ok(changed)
}
impl<S: Store> LidMappingStore<S> {
    pub fn new(store: S) -> Self {
        Self::with_options(store, None, CacheOptions::default(), Arc::new(SystemClock))
    }
    pub fn with_resolver(store: S, resolver: Arc<dyn Resolver>) -> Self {
        Self::with_options(
            store,
            Some(resolver),
            CacheOptions::default(),
            Arc::new(SystemClock),
        )
    }
    pub fn with_options(
        store: S,
        resolver: Option<Arc<dyn Resolver>>,
        options: CacheOptions,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let cache = Cache {
            revision: None,
            values: LruCache::new(options.capacity),
        };
        Self {
            store,
            resolver,
            options,
            clock,
            state: Arc::new(State {
                coalesced: AtomicU64::new(0),
                cache: Mutex::new(cache),
                flights: Mutex::new(HashMap::new()),
            }),
        }
    }
    pub fn coalesced_requests(&self) -> u64 {
        self.state.coalesced.load(Ordering::Relaxed)
    }
    pub fn store_mappings(&self, pairs: &[Mapping]) -> LookupResult<usize> {
        if !pairs.iter().any(|pair| normalize(pair).is_some()) {
            return Ok(0);
        }
        Ok(self.store.transaction(|tx| write_pairs(tx, pairs, false))?)
    }
    pub fn clear_cache(&self) -> LookupResult<()> {
        let mut cache = self.state.cache.lock().map_err(|_| Error::Storage)?;
        cache.values.clear();
        cache.revision = None;
        Ok(())
    }
    pub fn close(&self) -> LookupResult<()> {
        self.clear_cache()
    }
    pub fn cache_len(&self) -> LookupResult<usize> {
        let now = self.clock.now();
        let mut cache = self.state.cache.lock().map_err(|_| Error::Storage)?;
        let expired: Vec<_> = cache
            .values
            .iter()
            .filter(|(_, v)| v.expires.is_some_and(|expiry| expiry <= now))
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            cache.values.pop(&key);
        }
        Ok(cache.values.len())
    }
    fn known(&self, direction: Direction, users: &[String]) -> LookupResult<Resolved> {
        Ok(self.store.transaction(|tx| {
            let rev = revision(tx)?;
            let now = self.clock.now();
            let mut resolved = HashMap::new();
            let mut missing = Vec::new();
            {
                let mut cache = self.state.cache.lock().map_err(|_| Error::Storage)?;
                if cache.revision.is_none_or(|cached| cached < rev) {
                    cache.values.clear();
                    cache.revision = Some(rev);
                }
                let current = cache.revision == Some(rev);
                for user in users {
                    let key = CacheKey {
                        direction,
                        user: user.clone(),
                    };
                    if current {
                        if let Some(entry) = cache.values.get_mut(&key)
                            && entry.expires.is_none_or(|expiry| expiry > now)
                        {
                            entry.expires = now.checked_add(self.options.ttl);
                            resolved.insert(user.clone(), entry.value.clone());
                            continue;
                        }
                        cache.values.pop(&key);
                    }
                    missing.push(user);
                }
            }
            if missing.is_empty() {
                return Ok(resolved);
            }
            // No negative cache: a later contact/mapping update is immediately visible.
            let storage_keys: Vec<_> = missing
                .iter()
                .map(|user| match direction {
                    Direction::Forward => (*user).clone(),
                    Direction::Reverse => format!("{user}_reverse"),
                })
                .collect();
            let requested: Vec<_> = storage_keys.iter().map(String::as_str).collect();
            let values = tx.get_many("lid-mapping", &requested)?;
            let mut found = Vec::new();
            for (user, key) in missing.iter().zip(&storage_keys) {
                if let Some(bytes) = values.get(key) {
                    let value =
                        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidMapping)?;
                    if value.is_empty() {
                        continue;
                    }
                    let opposite = match direction {
                        Direction::Forward => format!("{value}_reverse"),
                        Direction::Reverse => value.clone(),
                    };
                    found.push((user.as_str(), value, opposite));
                }
            }
            let counterparts: Vec<_> = found.iter().map(|(_, _, key)| key.as_str()).collect();
            let checked = tx.get_many("lid-mapping", &counterparts)?;
            for (user, value, key) in &found {
                if checked.get(key).map(|bytes| bytes.as_slice()) != Some(user.as_bytes()) {
                    return Err(Error::InvalidMapping);
                }
                resolved.insert((*user).to_owned(), value.clone());
            }
            // No cache lock is held while invoking backend I/O. An older
            // snapshot cannot replace entries from a newer revision.
            let expires = self.clock.now().checked_add(self.options.ttl);
            let mut cache = self.state.cache.lock().map_err(|_| Error::Storage)?;
            if cache.revision == Some(rev) {
                for (user, value, _) in found {
                    let opposite = match direction {
                        Direction::Forward => Direction::Reverse,
                        Direction::Reverse => Direction::Forward,
                    };
                    cache.values.put(
                        CacheKey {
                            direction: opposite,
                            user: value.clone(),
                        },
                        CacheEntry {
                            value: user.to_owned(),
                            expires,
                        },
                    );
                    cache.values.put(
                        CacheKey {
                            direction,
                            user: user.to_owned(),
                        },
                        CacheEntry { value, expires },
                    );
                }
            }
            Ok(resolved)
        })?)
    }
    fn coalesce(
        &self,
        users: &[String],
        work: impl FnOnce() -> LookupResult<()>,
    ) -> LookupResult<()> {
        let mut ordered = users.to_vec();
        ordered.sort();
        ordered.dedup();
        let key = FlightKey(ordered);
        let (flight, leader) = {
            let mut flights = self.state.flights.lock().map_err(|_| Error::Storage)?;
            match flights.get(&key) {
                Some(flight) => {
                    self.state.coalesced.fetch_add(1, Ordering::Relaxed);
                    (flight.clone(), false)
                }
                None => {
                    let flight = Arc::new(Flight {
                        result: Mutex::new(None),
                        ready: Condvar::new(),
                    });
                    flights.insert(key.clone(), flight.clone());
                    (flight, true)
                }
            }
        };
        if leader {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or_else(|_| Err(Error::Storage.into()));
            *flight.result.lock().map_err(|_| Error::Storage)? = Some(result.clone());
            flight.ready.notify_all();
            let mut flights = self.state.flights.lock().map_err(|_| Error::Storage)?;
            if flights
                .get(&key)
                .is_some_and(|active| Arc::ptr_eq(active, &flight))
            {
                flights.remove(&key);
            }
            result
        } else {
            let mut result = flight.result.lock().map_err(|_| Error::Storage)?;
            while result.is_none() {
                result = flight.ready.wait(result).map_err(|_| Error::Storage)?;
            }
            result.clone().unwrap()
        }
    }
    pub fn get_lids_for_pns(&self, pns: &[String]) -> LookupResult<Vec<Mapping>> {
        let mut seen = HashSet::new();
        let rows: Vec<_> = pns
            .iter()
            .filter_map(|pn| decode(pn, true).map(|decoded| (pn, decoded)))
            .filter(|(pn, _)| seen.insert((*pn).clone()))
            .collect();
        let mut unique = HashSet::new();
        let users: Vec<_> = rows
            .iter()
            .filter(|(_, d)| unique.insert(d.user))
            .map(|(_, d)| d.user.to_owned())
            .collect();
        if users.is_empty() {
            return Ok(Vec::new());
        }
        let mut resolved = self.known(Direction::Forward, &users)?;
        let missing: Vec<_> = users
            .iter()
            .filter(|user| !resolved.contains_key(*user))
            .cloned()
            .collect();
        if !missing.is_empty()
            && let Some(resolver) = &self.resolver
        {
            self.coalesce(&missing, || {
                let known = self.known(Direction::Forward, &missing)?;
                let unresolved: Vec<_> = missing
                    .iter()
                    .filter(|user| !known.contains_key(*user))
                    .map(|user| format!("{user}@s.whatsapp.net"))
                    .collect();
                if !unresolved.is_empty() {
                    let supplied = resolver.resolve(&unresolved)?;
                    let requested: HashSet<_> = unresolved
                        .iter()
                        .filter_map(|pn| decode(pn, true).map(|d| d.user.to_owned()))
                        .collect();
                    let valid: Vec<_> = supplied
                        .into_iter()
                        .filter(|pair| {
                            normalize(pair).is_some_and(|(pn, _)| requested.contains(&pn))
                        })
                        .collect();
                    self.store.transaction(|tx| write_pairs(tx, &valid, true))?;
                }
                Ok(())
            })?;
            // Re-read one revision-consistent snapshot for every caller; a
            // mapping already known before a slow lookup may have changed.
            resolved = self.known(Direction::Forward, &users)?;
        }
        Ok(rows
            .into_iter()
            .filter_map(|(pn, d)| {
                resolved.get(d.user).map(|lid| Mapping {
                    pn: pn.clone(),
                    lid: jid::jid_encode(
                        lid,
                        if d.server == "hosted" {
                            "hosted.lid"
                        } else {
                            "lid"
                        },
                        d.device,
                        None,
                    ),
                })
            })
            .collect())
    }
    pub fn get_lid_for_pn(&self, pn: &str) -> LookupResult<Option<String>> {
        Ok(self
            .get_lids_for_pns(&[pn.into()])?
            .into_iter()
            .next()
            .map(|pair| pair.lid))
    }
    pub fn get_pns_for_lids(&self, lids: &[String]) -> LookupResult<Vec<Mapping>> {
        let mut seen = HashSet::new();
        let rows: Vec<_> = lids
            .iter()
            .filter_map(|lid| decode(lid, false).map(|d| (lid, d)))
            .filter(|(lid, _)| seen.insert((*lid).clone()))
            .collect();
        let mut unique = HashSet::new();
        let users: Vec<_> = rows
            .iter()
            .filter(|(_, d)| unique.insert(d.user))
            .map(|(_, d)| d.user.to_owned())
            .collect();
        if users.is_empty() {
            return Ok(Vec::new());
        }
        let resolved = self.known(Direction::Reverse, &users)?;
        Ok(rows
            .into_iter()
            .filter_map(|(lid, d)| {
                resolved.get(d.user).map(|pn| Mapping {
                    lid: lid.clone(),
                    pn: format!(
                        "{}:{}@{}",
                        pn,
                        d.device.unwrap_or(0),
                        if d.server == "hosted.lid" {
                            "hosted"
                        } else {
                            "s.whatsapp.net"
                        }
                    ),
                })
            })
            .collect())
    }
    pub fn get_pn_for_lid(&self, lid: &str) -> LookupResult<Option<String>> {
        Ok(self
            .get_pns_for_lids(&[lid.into()])?
            .into_iter()
            .next()
            .map(|pair| pair.pn))
    }
}
/// Resolve persisted PN aliases inside the cryptographic state transaction.
/// Network discovery is separate and must run before entering this transaction.
pub(crate) fn resolve_address(tx: &mut dyn Transaction, jid: &str) -> Result<String> {
    let Some(pn) = decode(jid, true) else {
        return crate::signal::protocol_address(jid);
    };
    if matches!(pn.domain_type, 1 | 129) {
        return crate::signal::protocol_address(jid);
    }
    if let Some(lid) = text(tx, pn.user)? {
        let reverse = format!("{lid}_reverse");
        if lid.is_empty() || text(tx, &reverse)?.as_deref() != Some(pn.user) {
            return Err(Error::InvalidMapping);
        }
        crate::signal::protocol_address(&jid::jid_encode(
            &lid,
            if pn.domain_type == 128 {
                "hosted.lid"
            } else {
                "lid"
            },
            pn.device,
            None,
        ))
    } else {
        crate::signal::protocol_address(jid)
    }
}
