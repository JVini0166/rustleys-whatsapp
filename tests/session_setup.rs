use rustleys_whatsapp::{
    auth::{Credentials, KeyPair},
    binary::{Content, Node},
    lid_mapping::Clock,
    session_setup::{self, Client, Error, Options},
    signal::{self, PreKeyBundle, Repository, SqliteStore, Store, Transaction},
};
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
fn n(tag: &str, attrs: Vec<(&str, String)>, content: Option<Content>) -> Node {
    Node {
        tag: tag.into(),
        attrs: attrs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        content,
    }
}
fn ns(tag: &str, c: Vec<Node>) -> Node {
    n(tag, vec![], Some(Content::Nodes(c)))
}
fn b(tag: &str, bytes: impl Into<Vec<u8>>) -> Node {
    n(tag, vec![], Some(Content::Bytes(bytes.into())))
}
fn children(n: &Node) -> &[Node] {
    match &n.content {
        Some(Content::Nodes(c)) => c,
        _ => &[],
    }
}
fn attr<'a>(n: &'a Node, k: &str) -> Option<&'a str> {
    n.attrs
        .iter()
        .find(|(key, _)| key == k)
        .map(|(_, v)| v.as_str())
}
fn result(c: Vec<Node>) -> Node {
    n(
        "iq",
        vec![("type", "result".into())],
        Some(Content::Nodes(c)),
    )
}
fn user_bundle(id: &str, c: &Credentials, one: Option<(u32, &KeyPair)>) -> Node {
    let mut parts = vec![
        b("registration", u32::from(c.registration_id).to_be_bytes()),
        b("identity", c.signed_identity_key.public.expose()),
        ns(
            "skey",
            vec![
                b("id", c.signed_pre_key.key_id.to_be_bytes()[1..].to_vec()),
                b("value", c.signed_pre_key.key_pair.public.expose()),
                b("signature", c.signed_pre_key.signature.expose()),
            ],
        ),
    ];
    if let Some((id, key)) = one {
        parts.push(ns(
            "key",
            vec![
                b("id", id.to_be_bytes()[1..].to_vec()),
                b("value", key.public.expose()),
            ],
        ));
    }
    n(
        "user",
        vec![("jid", id.into())],
        Some(Content::Nodes(parts)),
    )
}
fn store() -> (tempfile::TempDir, Arc<SqliteStore>) {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(SqliteStore::open(d.path().join("keys")).unwrap());
    (d, s)
}
#[test]
fn iq_and_retry_bundles_handle_absent_zero_prekeys_and_strict_lengths() {
    let c = Credentials::generate().unwrap();
    let key = KeyPair::generate().unwrap();
    for one in [None, Some((0, &key)), Some((7, &key))] {
        let user = user_bundle("200:1@s.whatsapp.net", &c, one);
        let parsed =
            session_setup::parse_bundles(&result(vec![ns("list", vec![user.clone()])])).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1.one_time_pre_key.map(|p| p.0), one.map(|p| p.0));
        let mut keys = children(&user).to_vec();
        let reg = keys.remove(0);
        keys.insert(0, b("type", [5]));
        let receipt = ns("receipt", vec![reg, ns("keys", keys)]);
        assert_eq!(
            session_setup::bundle_from_retry(&receipt)
                .unwrap()
                .unwrap()
                .registration_id,
            u32::from(c.registration_id)
        );
    }
    let malformed = result(vec![ns(
        "list",
        vec![
            user_bundle("200:1@s.whatsapp.net", &c, None),
            user_bundle("200:1@s.whatsapp.net", &c, None),
        ],
    )]);
    assert!(matches!(
        session_setup::parse_bundles(&malformed),
        Err(Error::DuplicateRecipient)
    ));
    let mut bad = user_bundle("200:1@s.whatsapp.net", &c, None);
    let Some(Content::Nodes(parts)) = &mut bad.content else {
        panic!()
    };
    parts[0] = b("registration", [0, 1]);
    assert!(matches!(
        session_setup::parse_bundles(&result(vec![ns("list", vec![bad])])),
        Err(Error::InvalidBundle)
    ));
    assert!(
        session_setup::bundle_from_retry(&ns("receipt", vec![]))
            .unwrap()
            .is_none()
    );
}
#[test]
fn late_session_signature_error_and_commit_failure_roll_back_entire_batch() {
    let (_d, s) = store();
    let local = Credentials::generate().unwrap();
    let target = Credentials::generate().unwrap();
    let repo = Repository::new(&local, s.clone()).unwrap();
    let valid = PreKeyBundle::from_credentials(&target, None).unwrap();
    let mut bad = valid.clone();
    bad.signed_pre_key.signature[0] ^= 1;
    assert!(
        repo.inject_sessions(&[
            ("200:1@s.whatsapp.net".into(), valid.clone()),
            ("300:1@s.whatsapp.net".into(), bad)
        ])
        .is_err()
    );
    assert!(
        !repo
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
    let failing = Arc::new(FailCommit {
        store: s,
        fail: AtomicBool::new(false),
    });
    let repo = Repository::new(&local, failing.clone()).unwrap();
    failing.fail.store(true, Ordering::SeqCst);
    assert!(
        repo.inject_sessions(&[("200:1@s.whatsapp.net".into(), valid)])
            .is_err()
    );
    failing.fail.store(false, Ordering::SeqCst);
    assert!(
        !repo
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
}
struct FailCommit {
    store: Arc<SqliteStore>,
    fail: AtomicBool,
}
impl Store for FailCommit {
    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut dyn Transaction) -> signal::Result<T>,
    ) -> signal::Result<T> {
        self.store.transaction(|tx| {
            let value = f(tx)?;
            if self.fail.load(Ordering::SeqCst) {
                Err(signal::Error::Storage)
            } else {
                Ok(value)
            }
        })
    }
}
#[test]
fn bulk_migration_rolls_back_aliases_and_covers_explicit_hosted_devices() {
    let (_d, s) = store();
    let c = Credentials::generate().unwrap();
    let repo = Repository::new(&c, s.clone()).unwrap();
    let target = Credentials::generate().unwrap();
    let bundle = PreKeyBundle::from_credentials(&target, None).unwrap();
    repo.inject_session("200:5@hosted", &bundle).unwrap();
    repo.inject_session("300:1@s.whatsapp.net", &bundle)
        .unwrap();
    s.transaction(|tx| tx.put("device-list", "300", b"corrupt"))
        .unwrap();
    assert!(
        repo.migrate_sessions(&[
            ("200:5@hosted".into(), "900:5@hosted.lid".into()),
            ("300@s.whatsapp.net".into(), "901@lid".into())
        ])
        .is_err()
    );
    assert!(repo.validate_session("200:5@hosted").unwrap().exists);
    assert!(!repo.validate_session("900:5@hosted.lid").unwrap().exists);
    s.transaction(|tx| tx.remove("device-list", "300")).unwrap();
    repo.migrate_sessions(&[("200:5@hosted".into(), "900:5@hosted.lid".into())])
        .unwrap();
    assert!(repo.validate_session("900:5@hosted.lid").unwrap().exists);
    repo.set_discovery_device_list("200@s.whatsapp.net", &[1])
        .unwrap();
    repo.set_discovery_device_list("200@lid", &[5]).unwrap();
    s.transaction(|tx| {
        assert_eq!(
            tx.get("device-list", "200")?.unwrap().as_slice(),
            b"[\"1\"]"
        );
        assert_eq!(
            tx.get("device-list-lid", "200")?.unwrap().as_slice(),
            b"[\"5\"]"
        );
        Ok(())
    })
    .unwrap();
}
#[test]
fn extraction_keeps_domain_local_filters_own_lid_and_obeys_zero_policy() {
    let row=rustleys_whatsapp::usync::Row{id:"900@lid".into(),data:serde_json::from_value(json!({"devices":{"deviceList":[{"id":0},{"id":4,"keyIndex":1},{"id":99,"keyIndex":1,"isHosted":true},{"id":5,"keyIndex":1,"isHosted":false}]}})).unwrap()};
    let d = session_setup::extract_devices(
        std::slice::from_ref(&row),
        "100:4@s.whatsapp.net",
        Some("900:4@lid"),
        false,
    )
    .unwrap();
    assert_eq!(d.iter().map(|d| d.device).collect::<Vec<_>>(), [0, 99, 5]);
    assert_eq!(d[1].jid, "900:99@hosted.lid");
    assert_eq!(d[2].jid, "900:5@lid");
    assert_eq!(
        session_setup::extract_devices(&[row], "100:4@s.whatsapp.net", Some("900:4@lid"), true)
            .unwrap()
            .len(),
        2
    );
}
#[derive(Clone)]
struct Mock {
    remote: Credentials,
    requests: Arc<Mutex<Vec<Node>>>,
    map: Arc<AtomicBool>,
    key_error: Arc<AtomicBool>,
    empty_keys: Arc<AtomicBool>,
    extra_keys: Arc<AtomicBool>,
    gate: Option<Arc<tokio::sync::Semaphore>>,
    started: Arc<tokio::sync::Semaphore>,
}
impl Mock {
    fn new() -> Self {
        Self {
            remote: Credentials::generate().unwrap(),
            requests: Default::default(),
            map: Arc::new(AtomicBool::new(false)),
            key_error: Arc::new(AtomicBool::new(false)),
            empty_keys: Arc::new(AtomicBool::new(false)),
            extra_keys: Arc::new(AtomicBool::new(false)),
            gate: None,
            started: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}
impl rustleys_whatsapp::prekeys::Query for Mock {
    async fn query(&self, node: Node) -> rustleys_whatsapp::socket::Result<Arc<Node>> {
        self.requests.lock().unwrap().push(node.clone());
        self.started.add_permits(1);
        if let Some(gate) = &self.gate {
            gate.acquire().await.unwrap().forget();
        }
        if attr(&node, "xmlns") == Some("encrypt") {
            if self.key_error.load(Ordering::SeqCst) {
                return Err(rustleys_whatsapp::socket::Error::Server(Some(503)));
            }
            let mut users = vec![];
            if !self.empty_keys.load(Ordering::SeqCst) {
                for user in children(&children(&node)[0]) {
                    users.push(user_bundle(attr(user, "jid").unwrap(), &self.remote, None));
                }
            }
            if self.extra_keys.load(Ordering::SeqCst) {
                users.push(user_bundle("99999:1@lid", &self.remote, None));
            }
            return Ok(Arc::new(result(vec![ns("list", users)])));
        }
        let sync = &children(&node)[0];
        let query = &children(sync)[0];
        let want_devices = children(query).iter().any(|n| n.tag == "devices");
        let mut users = vec![];
        for user in children(&children(sync)[1]) {
            let id = attr(user, "jid").unwrap();
            let mut parts = vec![];
            if want_devices {
                parts.push(ns(
                    "devices",
                    vec![ns(
                        "device-list",
                        vec![
                            n("device", vec![("id", "0".into())], None),
                            n(
                                "device",
                                vec![("id", "1".into()), ("key-index", "1".into())],
                                None,
                            ),
                            n(
                                "device",
                                vec![
                                    ("id", "99".into()),
                                    ("key-index", "1".into()),
                                    ("is_hosted", "true".into()),
                                ],
                                None,
                            ),
                        ],
                    )],
                ));
            }
            if self.map.load(Ordering::SeqCst) && id.ends_with("@s.whatsapp.net") {
                parts.push(n("lid", vec![("val", "900@lid".into())], None));
            }
            users.push(n(
                "user",
                vec![("jid", id.into())],
                Some(Content::Nodes(parts)),
            ));
        }
        Ok(Arc::new(result(vec![ns("usync", vec![ns("list", users)])])))
    }
}
struct FakeClock(Mutex<Instant>);
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
#[tokio::test]
async fn session_preparation_resolves_lids_reuses_sessions_and_preserves_device_ids() {
    let (_d, s) = store();
    let mock = Mock::new();
    mock.map.store(true, Ordering::SeqCst);
    let c = Client::new(
        &Credentials::generate().unwrap(),
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
    )
    .unwrap();
    assert!(
        c.assert_sessions(
            &["200:1@s.whatsapp.net".into(), "200:1@s.whatsapp.net".into()],
            false
        )
        .await
        .unwrap()
    );
    assert_eq!(mock.count(), 2);
    assert!(c.repository().validate_session("900:1@lid").unwrap().exists);
    assert!(
        c.repository()
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
    assert!(
        !c.assert_sessions(&["200:1@s.whatsapp.net".into()], false)
            .await
            .unwrap()
    );
    assert_eq!(mock.count(), 2);
    assert!(
        c.assert_sessions(&["200:1@s.whatsapp.net".into()], true)
            .await
            .unwrap()
    );
    assert_eq!(mock.count(), 3);
    let requests = mock.requests.lock().unwrap();
    let user = &children(&children(&requests[2])[0])[0];
    assert_eq!(attr(user, "jid"), Some("900:1@lid"));
    assert_eq!(attr(user, "reason"), Some("identity"));
}
#[tokio::test]
async fn unmapped_phone_fallback_never_reports_success_for_missing_or_unsolicited_sessions() {
    let (_d, s) = store();
    let mock = Mock::new();
    let c = Client::new(
        &Credentials::generate().unwrap(),
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
    )
    .unwrap();
    mock.empty_keys.store(true, Ordering::SeqCst);
    assert!(matches!(
        c.assert_sessions(&["200:1@s.whatsapp.net".into()], false)
            .await,
        Err(Error::MissingRecipient)
    ));
    assert!(
        !c.repository()
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
    mock.empty_keys.store(false, Ordering::SeqCst);
    mock.extra_keys.store(true, Ordering::SeqCst);
    assert!(matches!(
        c.assert_sessions(&["200:1@s.whatsapp.net".into()], false)
            .await,
        Err(Error::UnexpectedRecipient)
    ));
    assert!(
        !c.repository()
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
    mock.extra_keys.store(false, Ordering::SeqCst);
    assert!(
        c.assert_sessions(&["200:1@s.whatsapp.net".into()], false)
            .await
            .unwrap()
    );
    assert!(
        c.repository()
            .validate_session("200:1@s.whatsapp.net")
            .unwrap()
            .exists
    );
}
#[tokio::test]
async fn cache_preserves_zero_devices_separates_pn_lid_and_expires_or_invalidates() {
    let (_d, s) = store();
    let mock = Mock::new();
    let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
    let c = Client::with_clock(
        &Credentials::generate().unwrap(),
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
        clock.clone(),
    )
    .unwrap();
    assert_eq!(
        c.get_devices(&["200@s.whatsapp.net".into()], true, true)
            .await
            .unwrap()
            .devices
            .len(),
        2
    );
    assert_eq!(mock.count(), 1);
    assert_eq!(
        c.get_devices(&["200@s.whatsapp.net".into()], true, false)
            .await
            .unwrap()
            .devices
            .len(),
        3
    );
    assert_eq!(mock.count(), 1);
    assert_eq!(
        c.get_devices(&["200@lid".into()], true, false)
            .await
            .unwrap()
            .devices
            .len(),
        3
    );
    assert_eq!(mock.count(), 2);
    *clock.0.lock().unwrap() += Duration::from_secs(301);
    c.get_devices(&["200@s.whatsapp.net".into()], true, false)
        .await
        .unwrap();
    assert_eq!(mock.count(), 3);
    c.invalidate_devices("200@s.whatsapp.net").unwrap();
    c.get_devices(&["200@s.whatsapp.net".into()], true, false)
        .await
        .unwrap();
    assert_eq!(mock.count(), 4);
    let d = c
        .get_devices(&["200:0@s.whatsapp.net".into()], true, true)
        .await
        .unwrap();
    assert_eq!(d.devices[0].device, 0);
    assert_eq!(mock.count(), 4);
}
#[tokio::test]
async fn discovery_migrates_new_device_sessions_atomically_and_reports_refresh_failures() {
    let (_d, s) = store();
    let local = Credentials::generate().unwrap();
    let mock = Mock::new();
    let c = Client::new(
        &local,
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
    )
    .unwrap();
    c.repository()
        .inject_session(
            "200:1@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&mock.remote, None).unwrap(),
        )
        .unwrap();
    let before = c
        .repository()
        .session_info("200:1@s.whatsapp.net")
        .unwrap()
        .unwrap()
        .base_key;
    mock.map.store(true, Ordering::SeqCst);
    mock.key_error.store(true, Ordering::SeqCst);
    let report = c
        .get_devices(&["200@s.whatsapp.net".into()], true, false)
        .await
        .unwrap();
    assert!(report.session_refresh_error.is_some());
    assert!(report.device_list_error.is_none());
    assert_eq!(report.devices.len(), 3);
    assert_eq!(
        c.repository()
            .session_info("900:1@lid")
            .unwrap()
            .unwrap()
            .base_key,
        before
    );
    assert_eq!(
        c.repository()
            .session_info("200:1@s.whatsapp.net")
            .unwrap()
            .unwrap()
            .base_key,
        before
    );
}
#[tokio::test]
async fn cancelled_waiter_keeps_single_owner_until_pending_query_finishes() {
    let (_d, s) = store();
    let mut mock = Mock::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    mock.gate = Some(gate.clone());
    let c = Client::new(
        &Credentials::generate().unwrap(),
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
    )
    .unwrap();
    let first = c.clone();
    let task = tokio::spawn(async move {
        first
            .get_devices(&["200@s.whatsapp.net".into()], true, false)
            .await
    });
    mock.started.acquire().await.unwrap().forget();
    task.abort();
    let second = c.clone();
    let next = tokio::spawn(async move {
        second
            .get_devices(&["200@s.whatsapp.net".into()], true, false)
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(mock.count(), 1);
    gate.add_permits(1);
    next.await.unwrap().unwrap();
    assert_eq!(mock.count(), 1);
}

#[tokio::test]
async fn invalidation_during_discovery_prevents_stale_response_repopulating_cache() {
    let (_d, s) = store();
    let mut mock = Mock::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    mock.gate = Some(gate.clone());
    let client = Client::new(
        &Credentials::generate().unwrap(),
        s,
        mock.clone(),
        Options::new("100:4@s.whatsapp.net", None),
    )
    .unwrap();
    let c = client.clone();
    let first = tokio::spawn(async move {
        c.get_devices(&["200@s.whatsapp.net".into()], true, false)
            .await
    });
    mock.started.acquire().await.unwrap().forget();
    client.invalidate_devices("200@s.whatsapp.net").unwrap();
    gate.add_permits(1);
    first.await.unwrap().unwrap();
    let second = tokio::spawn(async move {
        client
            .get_devices(&["200@s.whatsapp.net".into()], true, false)
            .await
    });
    mock.started.acquire().await.unwrap().forget();
    assert_eq!(mock.count(), 2);
    gate.add_permits(1);
    second.await.unwrap().unwrap();
}
