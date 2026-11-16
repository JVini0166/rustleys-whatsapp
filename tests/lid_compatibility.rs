use rustleys_whatsapp::{
    auth::Credentials,
    lid_mapping::{CacheOptions, Clock, LidMappingStore, LookupResult, Mapping, Resolver},
    signal::{self, SqliteStore, Store, Transaction},
};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn mapping(pn: &str, lid: &str) -> Mapping {
    Mapping {
        pn: pn.into(),
        lid: lid.into(),
    }
}
fn backend(path: impl AsRef<std::path::Path>) -> Arc<SqliteStore> {
    let store = Arc::new(SqliteStore::open(path).unwrap());
    signal::Repository::new(&Credentials::generate().unwrap(), store.clone()).unwrap();
    store
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/lid-upstream.json")).unwrap()
}
#[test]
fn valid_original_lookup_vectors_preserve_devices_order_and_reverse_zero() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    for row in f["cases"].as_array().unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let store = LidMappingStore::new(backend(dir.path().join("state.sqlite")));
        let pairs: Vec<Mapping> = serde_json::from_value(row["pairs"].clone()).unwrap();
        store.store_mappings(&pairs).unwrap();
        let pns: Vec<String> = serde_json::from_value(row["pns"].clone()).unwrap();
        let lids: Vec<String> = serde_json::from_value(row["lids"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(store.get_lids_for_pns(&pns).unwrap()).unwrap(),
            row["forward"]
        );
        assert_eq!(
            serde_json::to_value(store.get_pns_for_lids(&lids).unwrap()).unwrap(),
            row["reverse"]
        );
        store.close().unwrap();
        assert_eq!(
            store.get_pn_for_lid("lidA@lid").unwrap().as_deref(),
            Some("pnA:0@s.whatsapp.net")
        );
    }
}
#[test]
fn remaps_are_bijective_and_invalidate_other_instances_without_negative_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let store = backend(&path);
    let a = LidMappingStore::new(store.clone());
    let b = LidMappingStore::new(Arc::new(SqliteStore::open(&path).unwrap()));
    assert!(a.get_lid_for_pn("pnA@s.whatsapp.net").unwrap().is_none());
    b.store_mappings(&[mapping("pnA@s.whatsapp.net", "lidA@lid")])
        .unwrap();
    assert_eq!(
        a.get_lid_for_pn("pnA@s.whatsapp.net").unwrap().as_deref(),
        Some("lidA@lid")
    );
    b.store_mappings(&[mapping("pnA@s.whatsapp.net", "lidC@lid")])
        .unwrap();
    assert_eq!(
        a.get_lid_for_pn("pnA@s.whatsapp.net").unwrap().as_deref(),
        Some("lidC@lid")
    );
    assert!(a.get_pn_for_lid("lidA@lid").unwrap().is_none());
    b.store_mappings(&[mapping("pnB@s.whatsapp.net", "lidC@lid")])
        .unwrap();
    assert!(a.get_lid_for_pn("pnA@s.whatsapp.net").unwrap().is_none());
    assert_eq!(
        a.get_pn_for_lid("lidC@lid").unwrap().as_deref(),
        Some("pnB:0@s.whatsapp.net")
    );
    assert_eq!(
        b.store_mappings(&[mapping("pnB@s.whatsapp.net", "lidC@lid")])
            .unwrap(),
        0
    );
    assert_eq!(
        fixture()["differences"]["stale_reverse"],
        "pnA:0@s.whatsapp.net"
    );
}
#[test]
fn swapped_fields_and_hosted_reverse_mappings_do_not_inherit_legacy_failures() {
    let dir = tempfile::tempdir().unwrap();
    let store = LidMappingStore::new(backend(dir.path().join("state.sqlite")));
    store
        .store_mappings(&[
            mapping("lidZ@lid", "pnZ@s.whatsapp.net"),
            mapping("pnB:99@hosted", "lidB:99@hosted.lid"),
        ])
        .unwrap();
    assert_eq!(
        store
            .get_lid_for_pn("pnZ@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidZ@lid")
    );
    assert_eq!(
        store.get_lid_for_pn("pnB:99@hosted").unwrap().as_deref(),
        Some("lidB:99@hosted.lid")
    );
    assert_eq!(
        store
            .get_pn_for_lid("lidB:99@hosted.lid")
            .unwrap()
            .as_deref(),
        Some("pnB:99@hosted")
    );
    let f = fixture();
    assert!(f["differences"]["swapped_forward"].is_null());
    assert!(f["differences"]["hosted_reverse"].is_null());
}
struct FakeClock {
    base: Instant,
    seconds: AtomicU64,
}
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_secs(self.seconds.load(Ordering::SeqCst))
    }
}
#[derive(Clone)]
struct CountingStore {
    inner: Arc<SqliteStore>,
    batches: Arc<AtomicUsize>,
}
struct CountTx<'a> {
    inner: &'a mut dyn Transaction,
    batches: &'a AtomicUsize,
}
impl Transaction for CountTx<'_> {
    fn get(&self, category: &str, id: &str) -> signal::Result<Option<Zeroizing<Vec<u8>>>> {
        self.inner.get(category, id)
    }
    fn get_many(
        &self,
        category: &str,
        ids: &[&str],
    ) -> signal::Result<HashMap<String, Zeroizing<Vec<u8>>>> {
        if category == "lid-mapping" && !ids.is_empty() {
            self.batches.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get_many(category, ids)
    }
    fn put(&mut self, category: &str, id: &str, value: &[u8]) -> signal::Result<()> {
        self.inner.put(category, id, value)
    }
    fn remove(&mut self, category: &str, id: &str) -> signal::Result<()> {
        self.inner.remove(category, id)
    }
}
impl Store for CountingStore {
    fn transaction<T>(
        &self,
        work: impl FnOnce(&mut dyn Transaction) -> signal::Result<T>,
    ) -> signal::Result<T> {
        self.inner.transaction(|tx| {
            work(&mut CountTx {
                inner: tx,
                batches: &self.batches,
            })
        })
    }
}
#[test]
fn bounded_cache_uses_sliding_expiration_and_real_batched_backend_reads() {
    let dir = tempfile::tempdir().unwrap();
    let batches = Arc::new(AtomicUsize::new(0));
    let counted = CountingStore {
        inner: backend(dir.path().join("state.sqlite")),
        batches: batches.clone(),
    };
    let clock = Arc::new(FakeClock {
        base: Instant::now(),
        seconds: AtomicU64::new(0),
    });
    let store = LidMappingStore::with_options(
        counted,
        None,
        CacheOptions {
            capacity: NonZeroUsize::new(4).unwrap(),
            ttl: Duration::from_secs(10),
        },
        clock.clone(),
    );
    store
        .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidA@lid")])
        .unwrap();
    store.get_lid_for_pn("pnA@s.whatsapp.net").unwrap();
    let initial = batches.load(Ordering::SeqCst);
    assert_eq!(initial, 2);
    clock.seconds.store(9, Ordering::SeqCst);
    store.get_lid_for_pn("pnA@s.whatsapp.net").unwrap();
    clock.seconds.store(11, Ordering::SeqCst);
    store.get_lid_for_pn("pnA@s.whatsapp.net").unwrap();
    assert_eq!(batches.load(Ordering::SeqCst), initial);
    clock.seconds.store(22, Ordering::SeqCst);
    assert_eq!(store.cache_len().unwrap(), 0);
    store.get_lid_for_pn("pnA@s.whatsapp.net").unwrap();
    assert_eq!(batches.load(Ordering::SeqCst), initial + 2);
    let pairs: Vec<_> = (0..1000)
        .map(|n| mapping(&format!("pn{n}@s.whatsapp.net"), &format!("lid{n}@lid")))
        .collect();
    store.store_mappings(&pairs).unwrap();
    let pns: Vec<_> = pairs.iter().map(|pair| pair.pn.clone()).collect();
    let before = batches.load(Ordering::SeqCst);
    assert_eq!(store.get_lids_for_pns(&pns).unwrap(), pairs);
    assert_eq!(batches.load(Ordering::SeqCst), before + 2);
    assert!(store.cache_len().unwrap() <= 4);
    store.close().unwrap();
    assert_eq!(store.cache_len().unwrap(), 0);
}
struct GatedResolver {
    calls: AtomicUsize,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    gate: Mutex<bool>,
    ready: Condvar,
    fail: bool,
    panic: bool,
}
impl GatedResolver {
    fn release(&self) {
        *self.gate.lock().unwrap() = true;
        self.ready.notify_all();
    }
}
impl Resolver for GatedResolver {
    fn resolve(&self, pns: &[String]) -> LookupResult<Vec<Mapping>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(sender) = self.entered.lock().unwrap().take() {
            sender.send(()).unwrap();
        }
        let mut gate = self.gate.lock().unwrap();
        while !*gate {
            gate = self.ready.wait(gate).unwrap();
        }
        drop(gate);
        assert!(!self.panic, "synthetic resolver panic");
        if self.fail {
            return Err(signal::Error::InvalidMapping.into());
        }
        Ok(pns
            .iter()
            .map(|pn| mapping(pn, &pn.replace("@s.whatsapp.net", "@lid")))
            .collect())
    }
}
#[test]
fn coalesced_resolution_preserves_each_callers_order_and_device_projection() {
    let dir = tempfile::tempdir().unwrap();
    let (started, entered) = mpsc::channel();
    let resolver = Arc::new(GatedResolver {
        calls: AtomicUsize::new(0),
        entered: Mutex::new(Some(started)),
        gate: Mutex::new(false),
        ready: Condvar::new(),
        fail: false,
        panic: false,
    });
    let store =
        LidMappingStore::with_resolver(backend(dir.path().join("state.sqlite")), resolver.clone());
    let first_store = store.clone();
    let first = std::thread::spawn(move || {
        first_store
            .get_lids_for_pns(&["pnA@s.whatsapp.net".into(), "pnB@s.whatsapp.net".into()])
            .unwrap()
    });
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let second_store = store.clone();
    let second = std::thread::spawn(move || {
        second_store
            .get_lids_for_pns(&["pnB@s.whatsapp.net".into(), "pnA@s.whatsapp.net".into()])
            .unwrap()
    });
    let devices_store = store.clone();
    let devices = std::thread::spawn(move || {
        devices_store
            .get_lids_for_pns(&["pnB:2@s.whatsapp.net".into(), "pnA:3@s.whatsapp.net".into()])
            .unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    while store.coalesced_requests() < 2 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let coalesced = store.coalesced_requests();
    resolver.release();
    assert_eq!(coalesced, 2);
    assert_eq!(
        first.join().unwrap(),
        vec![
            mapping("pnA@s.whatsapp.net", "pnA@lid"),
            mapping("pnB@s.whatsapp.net", "pnB@lid")
        ]
    );
    assert_eq!(
        second.join().unwrap(),
        vec![
            mapping("pnB@s.whatsapp.net", "pnB@lid"),
            mapping("pnA@s.whatsapp.net", "pnA@lid")
        ]
    );
    assert_eq!(
        devices.join().unwrap(),
        vec![
            mapping("pnB:2@s.whatsapp.net", "pnB:2@lid"),
            mapping("pnA:3@s.whatsapp.net", "pnA:3@lid")
        ]
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    let f = fixture();
    assert_eq!(
        f["differences"]["coalesced_first"],
        f["differences"]["coalesced_second"]
    );
}
#[test]
fn delayed_lookup_does_not_overwrite_a_newer_explicit_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let (started, entered) = mpsc::channel();
    let resolver = Arc::new(GatedResolver {
        calls: AtomicUsize::new(0),
        entered: Mutex::new(Some(started)),
        gate: Mutex::new(false),
        ready: Condvar::new(),
        fail: false,
        panic: false,
    });
    let store =
        LidMappingStore::with_resolver(backend(dir.path().join("state.sqlite")), resolver.clone());
    store
        .store_mappings(&[mapping("pnB@s.whatsapp.net", "oldB@lid")])
        .unwrap();
    let lookup = store.clone();
    let thread = std::thread::spawn(move || {
        lookup
            .get_lids_for_pns(&["pnA@s.whatsapp.net".into(), "pnB@s.whatsapp.net".into()])
            .unwrap()
    });
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    store
        .store_mappings(&[
            mapping("pnA@s.whatsapp.net", "newLid@lid"),
            mapping("pnB@s.whatsapp.net", "newB@lid"),
        ])
        .unwrap();
    resolver.release();
    assert_eq!(
        thread.join().unwrap(),
        vec![
            mapping("pnA@s.whatsapp.net", "newLid@lid"),
            mapping("pnB@s.whatsapp.net", "newB@lid")
        ]
    );
    assert!(store.get_pn_for_lid("pnA@lid").unwrap().is_none());
}
#[test]
fn resolver_failures_and_panics_release_flights_and_do_not_poison_the_store() {
    for panic in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let resolver = Arc::new(GatedResolver {
            calls: AtomicUsize::new(0),
            entered: Mutex::new(None),
            gate: Mutex::new(true),
            ready: Condvar::new(),
            fail: !panic,
            panic,
        });
        let store = LidMappingStore::with_resolver(
            backend(dir.path().join("state.sqlite")),
            resolver.clone(),
        );
        assert!(store.get_lid_for_pn("pnA@s.whatsapp.net").is_err());
        assert!(store.get_lid_for_pn("pnA@s.whatsapp.net").is_err());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        store
            .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidA@lid")])
            .unwrap();
        assert_eq!(
            store
                .get_lid_for_pn("pnA@s.whatsapp.net")
                .unwrap()
                .as_deref(),
            Some("lidA@lid")
        );
    }
}
#[test]
fn commit_failure_never_publishes_new_forward_or_reverse_cache_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let store = LidMappingStore::new(backend(&path));
    store
        .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidA@lid")])
        .unwrap();
    store.get_lid_for_pn("pnA@s.whatsapp.net").unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_lid_update AFTER UPDATE ON rustleys_signal_keys WHEN NEW.category='lid-mapping' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(
        store
            .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidB@lid")])
            .is_err()
    );
    assert_eq!(
        store
            .get_lid_for_pn("pnA@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidA@lid")
    );
    assert_eq!(
        store.get_pn_for_lid("lidA@lid").unwrap().as_deref(),
        Some("pnA:0@s.whatsapp.net")
    );
    assert!(store.get_pn_for_lid("lidB@lid").unwrap().is_none());
    conn.execute_batch("DROP TRIGGER fail_lid_update;").unwrap();
    store
        .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidB@lid")])
        .unwrap();
    assert_eq!(
        store
            .get_lid_for_pn("pnA@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidB@lid")
    );
}
#[test]
fn invalid_pairs_are_ignored_and_inconsistent_backend_rows_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let db = backend(dir.path().join("state.sqlite"));
    let store = LidMappingStore::new(db.clone());
    assert_eq!(
        store
            .store_mappings(&[
                mapping("invalid", "lidA@lid"),
                mapping("pnA@s.whatsapp.net", "other@s.whatsapp.net")
            ])
            .unwrap(),
        0
    );
    assert!(store.get_lids_for_pns(&[]).unwrap().is_empty());
    assert!(store.get_pns_for_lids(&[]).unwrap().is_empty());
    db.transaction(|tx| tx.put("lid-mapping", "pnA", b"lidA"))
        .unwrap();
    assert!(store.get_lid_for_pn("pnA@s.whatsapp.net").is_err());
    store
        .store_mappings(&[mapping("pnA@s.whatsapp.net", "lidA@lid")])
        .unwrap();
    assert_eq!(
        store
            .get_lid_for_pn("pnA@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidA@lid")
    );
}

#[test]
fn resolver_rows_outside_the_requested_phone_set_are_not_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let db = backend(dir.path().join("state.sqlite"));
    let resolver = Arc::new(|_: &[String]| -> LookupResult<Vec<Mapping>> {
        Ok(vec![
            mapping("unrequested@s.whatsapp.net", "otherLid@lid"),
            mapping("pnA@s.whatsapp.net", "lidA@lid"),
        ])
    });
    let store = LidMappingStore::with_resolver(db.clone(), resolver);
    assert_eq!(
        store
            .get_lid_for_pn("pnA@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidA@lid")
    );
    assert!(
        db.transaction(|tx| tx.get("lid-mapping", "unrequested"))
            .unwrap()
            .is_none()
    );
}
