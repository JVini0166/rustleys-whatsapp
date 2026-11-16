use rustleys_whatsapp::{
    auth::{Credentials, KeyPair},
    binary::{Content, Node},
    prekeys::{self, Counters, Error, Manager, Query, UploadPolicy, Uploader},
    signal::{PreKeyBundle, Repository, SqliteStore, Store},
    socket,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
fn manager(
    c: &Credentials,
) -> (
    tempfile::TempDir,
    Arc<SqliteStore>,
    Arc<Manager<Arc<SqliteStore>>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("keys.sqlite")).unwrap());
    let manager = Arc::new(Manager::new(c, store.clone()).unwrap());
    (dir, store, manager)
}
fn children(node: &Node) -> &[Node] {
    let Some(Content::Nodes(nodes)) = &node.content else {
        panic!("children")
    };
    nodes
}
fn bytes(node: &Node) -> &[u8] {
    let Some(Content::Bytes(bytes)) = &node.content else {
        panic!("bytes")
    };
    bytes
}
fn batch_ids(node: &Node) -> Vec<u32> {
    children(&children(node)[3])
        .iter()
        .map(|node| {
            let b = bytes(&children(node)[0]);
            u32::from_be_bytes([0, b[0], b[1], b[2]])
        })
        .collect()
}
fn result(children: Vec<Node>) -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![("type".into(), "result".into())],
        content: Some(Content::Nodes(children)),
    }
}
fn fast() -> UploadPolicy {
    UploadPolicy {
        first_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(4),
        timeout: Duration::from_secs(3),
        ..Default::default()
    }
}
#[test]
fn planning_matches_legacy_ranges_and_never_wraps_wire_ids() {
    for (first, next, count, expected_next) in [
        (1, 1, 5, 6),
        (10, 20, 5, 20),
        (10, 20, 12, 22),
        (0, 0, 1, 1),
        (0xfffffd, 0xfffffd, 3, 0x1000000),
    ] {
        let p = prekeys::plan(
            Counters {
                next_pre_key_id: next,
                first_unuploaded_pre_key_id: first,
            },
            count,
        )
        .unwrap();
        assert_eq!(p.first, first);
        assert_eq!(p.end, first + count);
        assert_eq!(p.counters.next_pre_key_id, expected_next);
        assert_eq!(p.counters.first_unuploaded_pre_key_id, first + count);
    }
    assert!(matches!(
        prekeys::plan(
            Counters {
                next_pre_key_id: 1,
                first_unuploaded_pre_key_id: 2
            },
            1
        ),
        Err(Error::InvalidCounters)
    ));
    assert!(matches!(
        prekeys::plan(
            Counters {
                next_pre_key_id: 0x1000000,
                first_unuploaded_pre_key_id: 0x1000000
            },
            1
        ),
        Err(Error::Exhausted)
    ));
    for count in [0, 8193, u32::MAX] {
        assert!(matches!(
            prekeys::plan(
                Counters {
                    next_pre_key_id: 1,
                    first_unuploaded_pre_key_id: 1
                },
                count
            ),
            Err(Error::InvalidCount)
        ));
    }
}
#[test]
fn generated_keys_survive_reopen_and_feed_transactional_signal_decryption() {
    let alice = Credentials::generate().unwrap();
    let mut bob = Credentials::generate().unwrap();
    let (dir, store, manager) = manager(&bob);
    let batch = manager.prepare(5).unwrap();
    assert_eq!(batch_ids(&batch.node), [1, 2, 3, 4, 5]);
    let pair = manager
        .get_pre_keys(1, 2)
        .unwrap()
        .remove(&1)
        .unwrap()
        .unwrap();
    let other = tempfile::tempdir().unwrap();
    let sender = Repository::new(
        &alice,
        SqliteStore::open(other.path().join("a.sqlite")).unwrap(),
    )
    .unwrap();
    let receiver = Repository::new(&bob, store.clone()).unwrap();
    sender
        .inject_session(
            "bob:1@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&bob, Some((1, &pair))).unwrap(),
        )
        .unwrap();
    let packet = sender
        .encrypt("bob:1@s.whatsapp.net", b"native reserved prekey")
        .unwrap();
    assert_eq!(
        receiver
            .decrypt("alice:1@s.whatsapp.net", packet.kind, &packet.bytes)
            .unwrap()
            .expose(),
        b"native reserved prekey"
    );
    assert!(manager.get_pre_keys(1, 2).unwrap()[&1].is_none());
    drop(receiver);
    drop(manager);
    drop(store);
    let store = Arc::new(SqliteStore::open(dir.path().join("keys.sqlite")).unwrap());
    let reopened = Manager::new(&bob, store).unwrap();
    assert_eq!(reopened.prepare(5).unwrap().first, 6);
    reopened.sync_counters(&mut bob).unwrap();
    assert_eq!(bob.next_pre_key_id, 11);
    assert_eq!(bob.first_unuploaded_pre_key_id, 11);
}
#[test]
fn available_keys_are_reused_and_missing_or_colliding_rows_fail_without_advancing() {
    let mut creds = Credentials::generate().unwrap();
    creds.next_pre_key_id = 4;
    let (dir, store, manager) = manager(&creds);
    let repo = Repository::new(&creds, store.clone()).unwrap();
    for id in 1..4 {
        repo.put_pre_key(id, &KeyPair::generate().unwrap()).unwrap();
    }
    let original = manager.get_pre_keys(1, 4).unwrap();
    let batch = manager.prepare(2).unwrap();
    assert_eq!(batch_ids(&batch.node), [1, 2]);
    assert_eq!(batch.counters.next_pre_key_id, 4);
    assert_eq!(
        original[&1].as_ref().unwrap().public,
        manager.get_pre_keys(1, 2).unwrap()[&1]
            .as_ref()
            .unwrap()
            .public
    );
    store.transaction(|tx| tx.remove("pre-key", "3")).unwrap();
    let before = manager.counters().unwrap();
    assert!(manager.prepare(3).is_err());
    assert_eq!(manager.counters().unwrap(), before);
    assert!(
        manager
            .get_pre_keys(4, 6)
            .unwrap()
            .values()
            .all(Option::is_none)
    );
    drop(dir);
    let creds = Credentials::generate().unwrap();
    let (_dir, store, manager) = self::manager(&creds);
    Repository::new(&creds, store)
        .unwrap()
        .put_pre_key(1, &KeyPair::generate().unwrap())
        .unwrap();
    assert!(manager.prepare(1).is_err());
    assert_eq!(manager.counters().unwrap().next_pre_key_id, 1);
}
#[test]
fn independent_managers_reserve_disjoint_batches_and_reject_foreign_credentials() {
    let creds = Credentials::generate().unwrap();
    let (dir, _, manager) = manager(&creds);
    let other = Arc::new(
        Manager::new(
            &creds,
            Arc::new(SqliteStore::open(dir.path().join("keys.sqlite")).unwrap()),
        )
        .unwrap(),
    );
    let a = std::thread::spawn(move || manager.prepare(50).unwrap());
    let b = std::thread::spawn(move || other.prepare(50).unwrap());
    let a = a.join().unwrap();
    let b = b.join().unwrap();
    assert!(a.first + a.count <= b.first || b.first + b.count <= a.first);
    let foreign = Credentials::generate().unwrap();
    assert!(
        Manager::new(
            &foreign,
            SqliteStore::open(dir.path().join("keys.sqlite")).unwrap()
        )
        .is_err()
    );
    let mut future = creds.clone();
    future.next_pre_key_id = 500;
    future.first_unuploaded_pre_key_id = 500;
    assert!(
        Manager::new(
            &future,
            SqliteStore::open(dir.path().join("keys.sqlite")).unwrap()
        )
        .is_err()
    );
}
#[test]
fn deferred_commit_failure_rolls_back_private_keys_and_cursors() {
    let creds = Credentials::generate().unwrap();
    let (dir, store, manager) = manager(&creds);
    let conn = rusqlite::Connection::open(dir.path().join("keys.sqlite")).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_reservation AFTER UPDATE ON rustleys_signal_keys WHEN NEW.category='meta' AND NEW.id='prekey-cursors' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(manager.prepare(5).is_err());
    assert_eq!(manager.counters().unwrap().next_pre_key_id, 1);
    assert!(
        store
            .transaction(|tx| tx.get("pre-key", "1"))
            .unwrap()
            .is_none()
    );
    conn.execute_batch("DROP TRIGGER fail_reservation").unwrap();
    assert_eq!(manager.prepare(5).unwrap().first, 1);
}
#[test]
fn malformed_private_records_and_metadata_are_not_published_as_valid_uploads() {
    let mut creds = Credentials::generate().unwrap();
    creds.next_pre_key_id = 2;
    let (_dir, store, manager) = manager(&creds);
    store
        .transaction(|tx| tx.put("pre-key", "1", b"corrupt"))
        .unwrap();
    assert!(manager.prepare(1).is_err());
    assert_eq!(manager.counters().unwrap().first_unuploaded_pre_key_id, 1);
    store
        .transaction(|tx| tx.put("meta", "prekey-cursors", &[0; 3]))
        .unwrap();
    assert!(manager.counters().is_err());
}
#[derive(Clone)]
struct Script {
    nodes: Arc<Mutex<Vec<Node>>>,
    replies: Arc<Mutex<std::collections::VecDeque<socket::Result<Arc<Node>>>>>,
    delay: Duration,
    calls: Arc<AtomicUsize>,
    observed: Option<Arc<Manager<Arc<SqliteStore>>>>,
}
impl Script {
    fn new(replies: Vec<socket::Result<Arc<Node>>>) -> Self {
        Self {
            nodes: Default::default(),
            replies: Arc::new(Mutex::new(replies.into())),
            delay: Duration::ZERO,
            calls: Default::default(),
            observed: None,
        }
    }
}
impl Query for Script {
    async fn query(&self, node: Node) -> socket::Result<Arc<Node>> {
        if children(&node)
            .first()
            .is_some_and(|n| n.tag == "registration")
            && let Some(manager) = &self.observed
        {
            let ids = batch_ids(&node);
            let keys = manager
                .get_pre_keys(*ids.first().unwrap(), ids.last().unwrap() + 1)
                .unwrap();
            assert!(keys.values().all(Option::is_some));
            assert!(manager.counters().unwrap().first_unuploaded_pre_key_id > *ids.last().unwrap());
        }
        self.nodes.lock().unwrap().push(node);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Arc::new(result(vec![]))));
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        result
    }
}

#[tokio::test]
async fn upload_retries_with_fresh_durable_ids_without_destroying_previous_private_keys() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let mut script = Script::new(vec![
        Err(socket::Error::OutcomeUnknown),
        Err(socket::Error::Network(std::io::ErrorKind::ConnectionReset)),
        Ok(Arc::new(result(vec![]))),
    ]);
    script.observed = Some(manager.clone());
    let uploader = Uploader::new(manager.clone(), script.clone(), fast()).unwrap();
    let report = uploader.upload(5).await.unwrap();
    assert_eq!(report.attempts, 3);
    assert_eq!(report.first, 11);
    assert_eq!(script.calls.load(Ordering::SeqCst), 3);
    assert!(
        manager
            .get_pre_keys(1, 16)
            .unwrap()
            .values()
            .all(Option::is_some)
    );
    assert_eq!(manager.counters().unwrap().next_pre_key_id, 16);
}
#[tokio::test]
async fn overlapping_uploads_share_one_flight_even_if_the_first_waiter_is_cancelled() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let mut script = Script::new(vec![]);
    script.delay = Duration::from_millis(80);
    let uploader = Uploader::new(manager, script.clone(), fast()).unwrap();
    let first = {
        let u = uploader.clone();
        tokio::spawn(async move { u.upload(5).await })
    };
    while script.calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let second = {
        let u = uploader.clone();
        tokio::spawn(async move { u.upload(812).await })
    };
    first.abort();
    let _ = first.await;
    let report = second.await.unwrap().unwrap();
    assert_eq!(report.count, 5);
    assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    let next = uploader.upload(1).await.unwrap();
    assert_eq!(next.first, 6);
}
#[tokio::test]
async fn timeout_stops_background_retries_and_releases_the_flight() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let mut script = Script::new(vec![]);
    script.delay = Duration::from_secs(1);
    let policy = UploadPolicy {
        timeout: Duration::from_millis(50),
        ..fast()
    };
    let uploader = Uploader::new(manager.clone(), script.clone(), policy).unwrap();
    assert!(matches!(uploader.upload(1).await, Err(Error::Timeout)));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(script.calls.load(Ordering::SeqCst), 1);
    assert_eq!(manager.counters().unwrap().next_pre_key_id, 2);
    assert!(matches!(uploader.upload(1).await, Err(Error::Timeout)));
    assert_eq!(script.calls.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn generation_errors_do_not_send_or_retry() {
    let creds = Credentials::generate().unwrap();
    let (_dir, store, manager) = manager(&creds);
    Repository::new(&creds, store)
        .unwrap()
        .put_pre_key(1, &KeyPair::generate().unwrap())
        .unwrap();
    let script = Script::new(vec![]);
    let uploader = Uploader::new(manager, script.clone(), fast()).unwrap();
    assert!(uploader.upload(5).await.is_err());
    assert_eq!(script.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn success_bootstrap_checks_count_activates_and_falls_back_on_missing_digest() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let count = Node {
        tag: "count".into(),
        attrs: vec![("value".into(), "0".into())],
        content: None,
    };
    let script = Script::new(vec![
        Ok(Arc::new(result(vec![count]))),
        Ok(Arc::new(result(vec![]))),
        Ok(Arc::new(result(vec![]))),
        Ok(Arc::new(result(vec![]))),
        Ok(Arc::new(result(vec![]))),
    ]);
    let uploader = Uploader::new(manager, script.clone(), fast()).unwrap();
    let report = uploader
        .initialize(&Node {
            tag: "success".into(),
            attrs: vec![("lid".into(), "123:1@lid".into())],
            content: None,
        })
        .await
        .unwrap();
    assert_eq!(report.prekeys.unwrap().unwrap().count, 812);
    assert!(report.active.is_ok());
    assert!(matches!(report.digest, Some(Err(Error::MissingDigest))));
    let nodes = script.nodes.lock().unwrap();
    assert_eq!(nodes.len(), 5);
    assert_eq!(children(&nodes[2])[0].tag, "active");
    assert_eq!(children(&nodes[3])[0].tag, "digest");
    assert_eq!(batch_ids(&nodes[4]), [813, 814, 815, 816, 817]);
}
#[tokio::test]
async fn auxiliary_failures_are_reported_and_do_not_fabricate_digest_success() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let script = Script::new(vec![Err(socket::Error::Closed), Err(socket::Error::Closed)]);
    let uploader = Uploader::new(manager, script.clone(), fast()).unwrap();
    let report = uploader
        .initialize(&Node {
            tag: "success".into(),
            attrs: vec![],
            content: None,
        })
        .await
        .unwrap();
    assert!(report.prekeys.is_err());
    assert!(report.active.is_err());
    assert!(report.digest.is_none());
    assert_eq!(script.calls.load(Ordering::SeqCst), 2);
}
#[test]
fn count_parsing_and_upload_thresholds_match_normal_source_behavior() {
    for (server, current, exists, should, count) in [
        (0, 0, false, true, 812),
        (5, 10, true, true, 5),
        (6, 10, true, false, 5),
        (100, 10, false, true, 5),
        (100, 0, false, false, 5),
    ] {
        let decision = prekeys::upload_decision(server, current, exists);
        assert_eq!(
            (decision.should_upload, decision.requested_count),
            (should, count)
        );
    }
    assert_eq!(
        prekeys::parse_count(&result(vec![Node {
            tag: "count".into(),
            attrs: vec![("value".into(), "812".into())],
            content: None
        }]))
        .unwrap(),
        812
    );
    for value in ["-1", "5.5", "NaN", "4294967296"] {
        assert!(
            prekeys::parse_count(&result(vec![Node {
                tag: "count".into(),
                attrs: vec![("value".into(), value.into())],
                content: None
            }]))
            .is_err()
        );
    }
}

fn fixture_node(value: &serde_json::Value) -> Node {
    Node {
        tag: value["tag"].as_str().unwrap().into(),
        attrs: value["attrs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect(),
        content: match &value["content"] {
            serde_json::Value::Null => None,
            serde_json::Value::Array(nodes) => {
                Some(Content::Nodes(nodes.iter().map(fixture_node).collect()))
            }
            serde_json::Value::Object(map) => Some(Content::Bytes(
                serde_json::from_value(map["bytes"].clone()).unwrap(),
            )),
            _ => panic!("fixture content"),
        },
    }
}
#[test]
fn upload_nodes_and_counters_match_original_fixtures_including_reused_and_boundary_keys() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/prekeys-upstream.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        rustleys_whatsapp::UPSTREAM_COMMIT
    );
    assert_eq!(fixture["synthetic_data"], true);
    for case in fixture["cases"].as_array().unwrap() {
        let mut creds =
            Credentials::from_json(&serde_json::to_vec(&case["credentials"]).unwrap()).unwrap();
        let original = prekeys::plan(
            Counters::from_credentials(&creds),
            case["count"].as_u64().unwrap() as u32,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(original.counters).unwrap(),
            case["update"]
        );
        // Supply the exact source-generated entropy as an already generated pool.
        // Fresh native generation is covered by active peer checks in the JS verifier.
        creds.next_pre_key_id = original.counters.next_pre_key_id;
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(directory.path().join("fixture.sqlite")).unwrap());
        let repository = Repository::new(&creds, store.clone()).unwrap();
        for (id, pair) in case["keys"].as_object().unwrap() {
            repository
                .put_pre_key(
                    id.parse().unwrap(),
                    &serde_json::from_value(pair.clone()).unwrap(),
                )
                .unwrap();
        }
        let manager = Manager::new(&creds, store).unwrap();
        let prepared = manager
            .prepare(case["count"].as_u64().unwrap() as u32)
            .unwrap();
        assert_eq!(prepared.node, fixture_node(&case["node"]));
        let wire: Vec<u8> = serde_json::from_value(case["wire"].clone()).unwrap();
        assert_eq!(
            rustleys_whatsapp::binary::encode(&prepared.node).unwrap(),
            wire
        );
        assert_eq!(
            serde_json::to_value(prepared.counters).unwrap(),
            case["update"]
        );
    }
}

#[tokio::test]
async fn retry_limit_is_finite_and_invalid_policies_never_start_work() {
    let creds = Credentials::generate().unwrap();
    let (_dir, _, manager) = manager(&creds);
    let script = Script::new(
        (0..4)
            .map(|_| Err(socket::Error::Server(Some(403))))
            .collect(),
    );
    let uploader = Uploader::new(manager.clone(), script.clone(), fast()).unwrap();
    assert!(matches!(
        uploader.upload(5).await,
        Err(Error::Network(socket::Error::Server(Some(403))))
    ));
    assert_eq!(script.calls.load(Ordering::SeqCst), 4);
    assert_eq!(manager.counters().unwrap().next_pre_key_id, 21);
    assert_eq!(uploader.upload(1).await.unwrap().first, 21);
    for policy in [
        UploadPolicy {
            max_attempts: 0,
            ..fast()
        },
        UploadPolicy {
            max_attempts: 5,
            ..fast()
        },
        UploadPolicy {
            max_backoff: Duration::MAX,
            ..fast()
        },
    ] {
        assert!(matches!(
            Uploader::new(manager.clone(), script.clone(), policy),
            Err(Error::InvalidPolicy)
        ));
    }
    assert_eq!(script.calls.load(Ordering::SeqCst), 5);
}
