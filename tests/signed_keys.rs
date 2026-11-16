use rustleys_whatsapp::{
    auth::{Bytes, Credentials, KeyPair, SignedKeyPair},
    binary::{Content, Node},
    crypto,
    prekeys::Manager,
    signal::{self, PreKeyBundle, Repository, SqliteStore, Store, Transaction},
    signed_keys::Authority,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
fn setup() -> (tempfile::TempDir, Credentials, Arc<SqliteStore>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("keys.sqlite")).unwrap());
    (dir, Credentials::generate().unwrap(), store)
}
fn children(node: &Node) -> &[Node] {
    match &node.content {
        Some(Content::Nodes(nodes)) => nodes,
        _ => panic!("nodes"),
    }
}
fn fresh_peer(target: &Credentials, store: Arc<SqliteStore>, label: &str) {
    let dir = tempfile::tempdir().unwrap();
    let sender = Repository::new(
        &Credentials::generate().unwrap(),
        SqliteStore::open(dir.path().join("sender.sqlite")).unwrap(),
    )
    .unwrap();
    sender
        .inject_session(
            "receiver:2@s.whatsapp.net",
            &PreKeyBundle::from_credentials(target, None).unwrap(),
        )
        .unwrap();
    let packet = sender
        .encrypt("receiver:2@s.whatsapp.net", label.as_bytes())
        .unwrap();
    let receiver = Repository::new(target, store).unwrap();
    assert_eq!(
        receiver
            .decrypt(
                &format!("{label}:1@s.whatsapp.net"),
                packet.kind,
                &packet.bytes
            )
            .unwrap()
            .expose(),
        label.as_bytes()
    );
}
#[test]
fn rotation_persists_before_publication_and_preserves_retired_and_uncertain_keys_after_restart() {
    let (dir, original, store) = setup();
    let authority = Authority::new(&original, store.clone()).unwrap();
    let rotation = authority.prepare_rotation().unwrap();
    assert_eq!(rotation.id(), original.signed_pre_key.key_id + 1);
    assert_eq!(
        authority.active_key().unwrap().key_id,
        original.signed_pre_key.key_id
    );
    let skey = &children(&children(rotation.node())[0])[0];
    assert_eq!(rotation.node().tag, "iq");
    assert_eq!(rotation.node().attrs[0].1, "@s.whatsapp.net");
    assert_eq!(skey.tag, "skey");
    assert!(crypto::verify_signature(
        original.signed_identity_key.public.expose(),
        &crypto::generate_signal_pub_key(
            authority
                .history_key(rotation.id())
                .unwrap()
                .key_pair
                .public
                .expose()
        ),
        authority
            .history_key(rotation.id())
            .unwrap()
            .signature
            .expose()
    ));
    authority.confirm(&rotation).unwrap();
    authority.confirm(&rotation).unwrap(); // idempotent acknowledgement
    let mut current = original.clone();
    authority.sync_credentials(&mut current).unwrap();
    assert_eq!(current.signed_pre_key.key_id, rotation.id());
    let uncertain = authority.prepare_rotation().unwrap();
    let mut accepted_without_ack = original.clone();
    accepted_without_ack.signed_pre_key = authority.history_key(uncertain.id()).unwrap();
    drop(authority);
    drop(store);
    let reopened = Arc::new(SqliteStore::open(dir.path().join("keys.sqlite")).unwrap());
    let authority = Authority::new(&original, reopened.clone()).unwrap();
    assert_eq!(
        authority.active_key().unwrap().key_id,
        current.signed_pre_key.key_id
    ); // stale JSON cannot roll back
    fresh_peer(&original, reopened.clone(), "retired");
    fresh_peer(&current, reopened.clone(), "current");
    fresh_peer(&accepted_without_ack, reopened.clone(), "uncertain");
    let next = authority.prepare_rotation().unwrap();
    assert_eq!(next.id(), uncertain.id() + 1);
    authority.confirm(&next).unwrap();
    assert!(matches!(
        authority.confirm(&uncertain),
        Err(signal::Error::SignedPreKeyConflict)
    ));
    fresh_peer(&accepted_without_ack, reopened, "still-retained");
}
#[test]
fn upload_manager_reads_current_signed_key_instead_of_its_initial_snapshot() {
    let (_dir, creds, store) = setup();
    let manager = Manager::new(&creds, store.clone()).unwrap();
    let authority = Authority::new(&creds, store).unwrap();
    let rotation = authority.prepare_rotation().unwrap();
    authority.confirm(&rotation).unwrap();
    let prepared = manager.prepare(1).unwrap();
    let key = authority.active_key().unwrap();
    assert_eq!(
        children(&prepared.node).last().unwrap(),
        &rustleys_whatsapp::prekeys::xmpp_signed_pre_key(&key).unwrap()
    );
}
#[test]
fn immutable_ids_corruption_foreign_credentials_and_exhaustion_fail_closed() {
    let (_dir, creds, store) = setup();
    let authority = Authority::new(&creds, store.clone()).unwrap();
    let mut conflicting = creds.clone();
    let key = crypto::signed_key_pair(
        &creds.signed_identity_key.private_key().unwrap(),
        creds.signed_pre_key.key_id,
    )
    .unwrap();
    conflicting.signed_pre_key = SignedKeyPair {
        key_pair: KeyPair::from_private(&key.private_key),
        signature: Bytes::new(key.signature.to_vec()),
        key_id: key.key_id,
        timestamp_s: None,
    };
    assert!(matches!(
        Authority::new(&conflicting, store.clone()),
        Err(signal::Error::SignedPreKeyConflict)
    ));
    assert!(matches!(
        Authority::new(&Credentials::generate().unwrap(), store.clone()),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    let other = Credentials::generate().unwrap();
    assert!(matches!(
        authority.sync_credentials(&mut other.clone()),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    let rotation = authority.prepare_rotation().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let other_authority = Authority::new(
        &other,
        SqliteStore::open(other_dir.path().join("other")).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        other_authority.confirm(&rotation),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    store
        .transaction(|tx| tx.put("signed-pre-key", &rotation.id().to_string(), b"corrupt"))
        .unwrap();
    assert!(authority.confirm(&rotation).is_err());
    assert_eq!(
        authority.active_key().unwrap().key_id,
        creds.signed_pre_key.key_id
    );
    store
        .transaction(|tx| tx.put("meta", "signed-prekey-next", &0x1000000u32.to_be_bytes()))
        .unwrap();
    assert!(matches!(
        authority.prepare_rotation(),
        Err(signal::Error::PreKeyIdExhausted)
    ));
}
struct FailCommit {
    store: Arc<SqliteStore>,
    fail: AtomicBool,
}
impl Store for FailCommit {
    fn transaction<T>(
        &self,
        work: impl FnOnce(&mut dyn Transaction) -> signal::Result<T>,
    ) -> signal::Result<T> {
        self.store.transaction(|tx| {
            let result = work(tx)?;
            if self.fail.load(Ordering::SeqCst) {
                Err(signal::Error::Storage)
            } else {
                Ok(result)
            }
        })
    }
}
#[test]
fn failed_commit_rolls_back_reservation_and_activation_and_ack_races_are_compare_and_swap() {
    let (_dir, creds, store) = setup();
    let failing = Arc::new(FailCommit {
        store: store.clone(),
        fail: AtomicBool::new(false),
    });
    let authority = Authority::new(&creds, failing.clone()).unwrap();
    failing.fail.store(true, Ordering::SeqCst);
    assert!(authority.prepare_rotation().is_err());
    failing.fail.store(false, Ordering::SeqCst);
    let first = authority.prepare_rotation().unwrap();
    assert_eq!(first.id(), creds.signed_pre_key.key_id + 1);
    let second = authority.prepare_rotation().unwrap();
    failing.fail.store(true, Ordering::SeqCst);
    assert!(authority.confirm(&first).is_err());
    failing.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        authority.active_key().unwrap().key_id,
        creds.signed_pre_key.key_id
    );
    authority.confirm(&second).unwrap();
    assert!(matches!(
        authority.confirm(&first),
        Err(signal::Error::SignedPreKeyConflict)
    ));
    assert!(authority.history_key(first.id()).is_ok());
}
#[test]
fn malformed_stored_signature_and_private_public_mismatch_are_rejected() {
    use wacore_libsignal::engine::codec;
    let (_dir, creds, store) = setup();
    let authority = Authority::new(&creds, store.clone()).unwrap();
    let id = creds.signed_pre_key.key_id;
    let encoded = store
        .transaction(|tx| Ok(tx.get("signed-pre-key", &id.to_string())?.unwrap()))
        .unwrap();
    let mut record = codec::decode_signed_pre_key(&encoded).unwrap();
    record.signature[0] ^= 1;
    store
        .transaction(|tx| {
            tx.put(
                "signed-pre-key",
                &id.to_string(),
                &codec::encode_signed_pre_key(&record),
            )
        })
        .unwrap();
    assert!(matches!(
        authority.history_key(id),
        Err(signal::Error::InvalidKey)
    ));
    record = codec::decode_signed_pre_key(&encoded).unwrap();
    record.key_pair.private[0] ^= 64;
    store
        .transaction(|tx| {
            tx.put(
                "signed-pre-key",
                &id.to_string(),
                &codec::encode_signed_pre_key(&record),
            )
        })
        .unwrap();
    assert!(matches!(
        authority.history_key(id),
        Err(signal::Error::InvalidKey)
    ));
}

#[test]
fn unknown_signed_key_never_consumes_one_time_key_or_installs_session() {
    use wacore_libsignal::engine::wire;
    let (_dir, target, store) = setup();
    let receiver = Repository::new(&target, store.clone()).unwrap();
    let one_time = KeyPair::generate().unwrap();
    receiver.put_pre_key(7, &one_time).unwrap();
    let sender_dir = tempfile::tempdir().unwrap();
    let sender = Repository::new(
        &Credentials::generate().unwrap(),
        SqliteStore::open(sender_dir.path().join("sender.sqlite")).unwrap(),
    )
    .unwrap();
    sender
        .inject_session(
            "receiver:2@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&target, Some((7, &one_time))).unwrap(),
        )
        .unwrap();
    let packet = sender
        .encrypt(
            "receiver:2@s.whatsapp.net",
            b"only authentic packet consumes the key",
        )
        .unwrap();
    let mut wrapper = wire::PreKeySignalMessageView::decode(&packet.bytes)
        .unwrap()
        .to_owned();
    wrapper.signed_pre_key_id += 10;
    assert!(matches!(
        receiver.decrypt("sender:1@s.whatsapp.net", packet.kind, &wrapper.encode()),
        Err(signal::Error::MissingSignedPreKey)
    ));
    assert!(receiver.has_pre_key(7).unwrap());
    assert!(
        receiver
            .session_info("sender:1@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        receiver
            .decrypt("sender:1@s.whatsapp.net", packet.kind, &packet.bytes)
            .unwrap()
            .expose(),
        b"only authentic packet consumes the key"
    );
    assert!(!receiver.has_pre_key(7).unwrap());
}

#[derive(Clone)]
struct Controlled {
    nodes: Arc<std::sync::Mutex<Vec<Node>>>,
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
    fail: bool,
}
impl Controlled {
    fn new(fail: bool) -> Self {
        Self {
            nodes: Default::default(),
            started: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            fail,
        }
    }
}
impl rustleys_whatsapp::prekeys::Query for Controlled {
    async fn query(&self, node: Node) -> rustleys_whatsapp::socket::Result<Arc<Node>> {
        let rotate = children(&node)
            .first()
            .is_some_and(|node| node.tag == "rotate");
        self.nodes.lock().unwrap().push(node);
        self.started.add_permits(1);
        if self.fail {
            return Err(rustleys_whatsapp::socket::Error::Closed);
        }
        if rotate {
            self.release.acquire().await.unwrap().forget();
        }
        Ok(Arc::new(Node {
            tag: "iq".into(),
            attrs: vec![("type".into(), "result".into())],
            content: None,
        }))
    }
}
#[tokio::test]
async fn async_rotation_survives_waiter_cancellation_and_serializes_prekey_uploads() {
    use rustleys_whatsapp::{
        prekeys::{UploadPolicy, Uploader},
        signed_keys::Rotator,
    };
    use std::time::Duration;
    let (_dir, creds, store) = setup();
    let manager = Arc::new(Manager::new(&creds, store.clone()).unwrap());
    let endpoint = Controlled::new(false);
    let rotator = Rotator::new(
        &creds,
        manager.clone(),
        endpoint.clone(),
        Duration::from_secs(3),
    )
    .unwrap();
    let rotating = tokio::spawn(async move { rotator.rotate().await });
    tokio::time::timeout(Duration::from_secs(2), endpoint.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    rotating.abort();
    let uploader = Uploader::new(manager, endpoint.clone(), UploadPolicy::default()).unwrap();
    let uploading = tokio::spawn(async move { uploader.upload(1).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(endpoint.nodes.lock().unwrap().len(), 1);
    endpoint.release.add_permits(1);
    uploading.await.unwrap().unwrap();
    let authority = Authority::new(&creds, store).unwrap();
    assert_eq!(
        authority.active_key().unwrap().key_id,
        creds.signed_pre_key.key_id + 1
    );
    let nodes = endpoint.nodes.lock().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(
        children(&nodes[1]).last().unwrap(),
        &rustleys_whatsapp::prekeys::xmpp_signed_pre_key(&authority.active_key().unwrap()).unwrap()
    );
}
#[tokio::test]
async fn async_timeout_retains_candidate_releases_gate_and_never_reuses_its_id() {
    use rustleys_whatsapp::{prekeys::Error, signed_keys::Rotator};
    use std::time::Duration;
    let (_dir, creds, store) = setup();
    let manager = Arc::new(Manager::new(&creds, store.clone()).unwrap());
    let endpoint = Controlled::new(false);
    let rotator = Rotator::new(
        &creds,
        manager.clone(),
        endpoint.clone(),
        Duration::from_millis(250),
    )
    .unwrap();
    assert!(matches!(rotator.rotate().await, Err(Error::Timeout)));
    let authority = Authority::new(&creds, store).unwrap();
    assert_eq!(
        authority.active_key().unwrap().key_id,
        creds.signed_pre_key.key_id
    );
    assert!(
        authority
            .history_key(creds.signed_pre_key.key_id + 1)
            .is_ok()
    );
    endpoint.release.add_permits(1);
    let retry = Rotator::new(&creds, manager, endpoint, Duration::from_secs(3)).unwrap();
    assert_eq!(
        retry.rotate().await.unwrap().key_id,
        creds.signed_pre_key.key_id + 2
    );
}
#[tokio::test]
async fn async_server_error_does_not_activate_or_retry_and_policies_are_bounded() {
    use rustleys_whatsapp::{prekeys::Error, signed_keys::Rotator};
    use std::time::Duration;
    let (_dir, creds, store) = setup();
    let manager = Arc::new(Manager::new(&creds, store.clone()).unwrap());
    let endpoint = Controlled::new(true);
    assert!(matches!(
        Rotator::new(&creds, manager.clone(), endpoint.clone(), Duration::ZERO),
        Err(Error::InvalidPolicy)
    ));
    assert!(matches!(
        Rotator::new(
            &creds,
            manager.clone(),
            endpoint.clone(),
            Duration::from_secs(301)
        ),
        Err(Error::InvalidPolicy)
    ));
    assert!(matches!(
        Rotator::new(
            &Credentials::generate().unwrap(),
            manager.clone(),
            endpoint.clone(),
            Duration::from_secs(1)
        ),
        Err(Error::CredentialConflict)
    ));
    let rotator = Rotator::new(&creds, manager, endpoint.clone(), Duration::from_secs(3)).unwrap();
    assert!(matches!(
        rotator.rotate().await,
        Err(Error::Network(rustleys_whatsapp::socket::Error::Closed))
    ));
    assert_eq!(endpoint.nodes.lock().unwrap().len(), 1);
    assert_eq!(
        Authority::new(&creds, store)
            .unwrap()
            .active_key()
            .unwrap()
            .key_id,
        creds.signed_pre_key.key_id
    );
}
