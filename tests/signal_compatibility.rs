use rustleys_whatsapp::{
    auth::{Credentials, KeyPair},
    signal::{self, MessageType, PreKeyBundle, Repository, SqliteStore, Store, Transaction},
};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/signal-upstream.json")).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect()
}
fn creds(row: &Value, who: &str) -> Credentials {
    Credentials::from_json(row[who].as_str().unwrap().as_bytes()).unwrap()
}
#[test]
fn original_node_prekey_messages_decrypt_in_rust_with_reordering_and_restart() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(f["libsignal_version"], "6.0.0");
    for row in f["cases"].as_array().unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signal.sqlite");
        let bob = creds(row, "bob_credentials");
        let repo = Repository::new(&bob, SqliteStore::open(&path).unwrap()).unwrap();
        if let Some(pre) = row["prekey"].as_str() {
            let pre: KeyPair = serde_json::from_str(pre).unwrap();
            repo.put_pre_key(7, &pre).unwrap();
        }
        let packets = row["packets"].as_array().unwrap();
        for (n, index) in [3, 0, 7, 1, 6, 2, 5, 4].into_iter().enumerate() {
            let repo = if n == 0 {
                &repo
            } else {
                &Repository::new(&bob, SqliteStore::open(&path).unwrap()).unwrap()
            };
            assert_eq!(
                repo.decrypt(
                    "synthetic-alice:1@s.whatsapp.net",
                    MessageType::PreKey,
                    &bytes(&packets[index]["ciphertext"])
                )
                .unwrap()
                .expose(),
                bytes(&packets[index]["plaintext"])
            );
        }
        assert!(!repo.has_pre_key(7).unwrap());
        assert!(
            repo.session_info("synthetic-alice:1@s.whatsapp.net")
                .unwrap()
                .is_some()
        );
        assert!(
            repo.decrypt(
                "synthetic-alice:1@s.whatsapp.net",
                MessageType::PreKey,
                &bytes(&packets[0]["ciphertext"])
            )
            .is_err()
        );
    }
}
fn pair(
    one_time: bool,
) -> (
    tempfile::TempDir,
    Repository<Arc<SqliteStore>>,
    Repository<Arc<SqliteStore>>,
    Credentials,
    Credentials,
) {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let alice = Repository::new(
        &a,
        Arc::new(SqliteStore::open(dir.path().join("alice.sqlite")).unwrap()),
    )
    .unwrap();
    let bob = Repository::new(
        &b,
        Arc::new(SqliteStore::open(dir.path().join("bob.sqlite")).unwrap()),
    )
    .unwrap();
    let pre = KeyPair::generate().unwrap();
    if one_time {
        bob.put_pre_key(9, &pre).unwrap();
    }
    alice
        .inject_session(
            "bob:2@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, one_time.then_some((9, &pre))).unwrap(),
        )
        .unwrap();
    (dir, alice, bob, a, b)
}
#[test]
fn bidirectional_ratchets_reordering_duplicates_and_binary_payloads() {
    for one_time in [false, true] {
        let (_dir, alice, bob, _a, _b) = pair(one_time);
        for round in 0..8 {
            let plaintext = vec![round; 17 + usize::from(round) * 16];
            let encrypted = alice.encrypt("bob:2@s.whatsapp.net", &plaintext).unwrap();
            assert_eq!(
                encrypted.kind,
                if round == 0 {
                    MessageType::PreKey
                } else {
                    MessageType::Normal
                }
            );
            assert_eq!(
                bob.decrypt("alice:1@s.whatsapp.net", encrypted.kind, &encrypted.bytes)
                    .unwrap()
                    .expose(),
                plaintext
            );
            let response = bob
                .encrypt("alice:1@s.whatsapp.net", &[0, 255, round])
                .unwrap();
            assert_eq!(response.kind, MessageType::Normal);
            assert_eq!(
                alice
                    .decrypt("bob:2@s.whatsapp.net", response.kind, &response.bytes)
                    .unwrap()
                    .expose(),
                [0, 255, round]
            );
        }
        let a = alice.encrypt("bob:2@s.whatsapp.net", b"a").unwrap();
        let b = alice.encrypt("bob:2@s.whatsapp.net", b"b").unwrap();
        let c = alice.encrypt("bob:2@s.whatsapp.net", b"c").unwrap();
        for (msg, expected) in [(&c, b"c"), (&a, b"a"), (&b, b"b")] {
            assert_eq!(
                bob.decrypt("alice:1@s.whatsapp.net", msg.kind, &msg.bytes)
                    .unwrap()
                    .expose(),
                expected
            );
        }
        assert!(
            bob.decrypt("alice:1@s.whatsapp.net", a.kind, &a.bytes)
                .is_err()
        );
    }
}
#[test]
fn failed_mac_and_missing_keys_leave_prekey_and_session_unchanged() {
    let (_dir, alice, bob, _a, _b) = pair(true);
    let encrypted = alice.encrypt("bob:2@s.whatsapp.net", b"synthetic").unwrap();
    let mut corrupt = encrypted.bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        bob.decrypt("alice:1@s.whatsapp.net", encrypted.kind, &corrupt)
            .is_err()
    );
    assert!(bob.has_pre_key(9).unwrap());
    assert!(
        bob.session_info("alice:1@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        bob.decrypt("alice:1@s.whatsapp.net", encrypted.kind, &encrypted.bytes)
            .unwrap()
            .expose(),
        b"synthetic"
    );
    assert!(!bob.has_pre_key(9).unwrap());
    assert!(
        bob.decrypt("absent:1@s.whatsapp.net", MessageType::Normal, &[0x33])
            .is_err()
    );
}
#[test]
fn deferred_commit_failure_rolls_back_session_identity_and_prekey_deletion() {
    let (dir, alice, bob, _a, b) = pair(true);
    let path = dir.path().join("bob.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER reject_session_commit AFTER INSERT ON rustleys_signal_keys WHEN NEW.category='session' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    let encrypted = alice
        .encrypt("bob:2@s.whatsapp.net", b"commit before publication")
        .unwrap();
    assert!(matches!(
        bob.decrypt("alice:1@s.whatsapp.net", encrypted.kind, &encrypted.bytes),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    assert!(bob.has_pre_key(9).unwrap());
    assert!(
        bob.session_info("alice:1@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM commit_guard", [], |row| row
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM rustleys_signal_keys WHERE category='identity-key'",
            [],
            |row| row.get::<_, u32>(0)
        )
        .unwrap(),
        0
    );
    conn.execute_batch("DROP TRIGGER reject_session_commit;")
        .unwrap();
    drop(bob);
    let restored = Repository::new(&b, SqliteStore::open(path).unwrap()).unwrap();
    assert_eq!(
        restored
            .decrypt("alice:1@s.whatsapp.net", encrypted.kind, &encrypted.bytes)
            .unwrap()
            .expose(),
        b"commit before publication"
    );
    assert!(!restored.has_pre_key(9).unwrap());
}
struct FailingStore {
    inner: Arc<SqliteStore>,
    fail: Arc<AtomicBool>,
}
impl Store for FailingStore {
    fn transaction<T>(
        &self,
        work: impl FnOnce(&mut dyn Transaction) -> signal::Result<T>,
    ) -> signal::Result<T> {
        self.inner.transaction(|tx| {
            let output = work(tx)?;
            if self.fail.load(Ordering::SeqCst) {
                Err(signal::Error::Storage)
            } else {
                Ok(output)
            }
        })
    }
}
#[test]
fn encryption_does_not_publish_or_advance_the_chain_on_failed_commit() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("a.sqlite")).unwrap());
    let fail = Arc::new(AtomicBool::new(false));
    let alice = Repository::new(
        &a,
        FailingStore {
            inner: store.clone(),
            fail: fail.clone(),
        },
    )
    .unwrap();
    alice
        .inject_session(
            "bob@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let before = store
        .transaction(|tx| tx.get("session", "bob.0"))
        .unwrap()
        .unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        alice.encrypt("bob@s.whatsapp.net", b"not published"),
        Err(signal::Error::Storage)
    ));
    fail.store(false, Ordering::SeqCst);
    let after = store
        .transaction(|tx| tx.get("session", "bob.0"))
        .unwrap()
        .unwrap();
    assert_eq!(before.as_slice(), after.as_slice());
    let bob = Repository::new(&b, SqliteStore::open(dir.path().join("b.sqlite")).unwrap()).unwrap();
    let encrypted = alice.encrypt("bob@s.whatsapp.net", b"retry").unwrap();
    assert_eq!(
        bob.decrypt("alice@s.whatsapp.net", encrypted.kind, &encrypted.bytes)
            .unwrap()
            .expose(),
        b"retry"
    );
}
#[test]
fn domain_addresses_and_session_deletion_match_repository_contract() {
    for (jid, address) in [
        ("123@s.whatsapp.net", "123.0"),
        ("123:4@lid", "123_1.4"),
        ("123:99@hosted", "123_128.99"),
        ("123:99@hosted.lid", "123_129.99"),
        ("123_8:2@s.whatsapp.net", "123_8.2"),
    ] {
        assert_eq!(signal::protocol_address(jid).unwrap(), address);
    }
    for jid in [
        "invalid",
        "@s.whatsapp.net",
        "123:99@s.whatsapp.net",
        "123:99@lid",
    ] {
        assert!(signal::protocol_address(jid).is_err());
    }
    let (_dir, alice, _bob, _a, _b) = pair(false);
    assert!(
        alice
            .session_info("bob:2@s.whatsapp.net")
            .unwrap()
            .is_some()
    );
    alice
        .delete_sessions(&["bob:2@s.whatsapp.net".into()])
        .unwrap();
    assert!(
        alice
            .session_info("bob:2@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    assert!(alice.encrypt("bob:2@s.whatsapp.net", b"missing").is_err());
}
#[test]
fn database_cannot_be_rebound_to_another_identity_and_files_are_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite");
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    Repository::new(&a, SqliteStore::open(&path).unwrap()).unwrap();
    assert!(matches!(
        Repository::new(&b, SqliteStore::open(&path).unwrap()),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("link.sqlite");
        symlink(&path, &link).unwrap();
        assert!(SqliteStore::open(link).is_err());
    }
}
#[test]
fn invalid_signed_bundles_and_corrupted_records_are_not_treated_as_new_sessions() {
    let (dir, alice, _bob, a, b) = pair(false);
    let mut bundle = PreKeyBundle::from_credentials(&b, None).unwrap();
    bundle.signed_pre_key.signature[0] ^= 1;
    assert!(alice.inject_session("new@s.whatsapp.net", &bundle).is_err());
    assert!(alice.session_info("new@s.whatsapp.net").unwrap().is_none());
    let conn = rusqlite::Connection::open(dir.path().join("alice.sqlite")).unwrap();
    conn.execute(
        "UPDATE rustleys_signal_keys SET value=x'ff' WHERE category='session'",
        [],
    )
    .unwrap();
    drop(alice);
    let restored = Repository::new(
        &a,
        SqliteStore::open(dir.path().join("alice.sqlite")).unwrap(),
    )
    .unwrap();
    assert!(restored.session_info("bob:2@s.whatsapp.net").is_err());
    assert!(
        restored
            .encrypt("bob:2@s.whatsapp.net", b"not reset")
            .is_err()
    );
}

#[test]
fn concurrent_independent_connections_do_not_reuse_sending_counters() {
    let (dir, alice, bob, a, _b) = pair(true);
    drop(alice);
    let path = dir.path().join("alice.sqlite");
    let mut workers = Vec::new();
    for worker in 0..4 {
        let path = path.clone();
        let creds = a.clone();
        workers.push(std::thread::spawn(move || {
            let repo = Repository::new(&creds, SqliteStore::open(path).unwrap()).unwrap();
            (0..8)
                .map(|n| {
                    let plaintext = format!("synthetic worker {worker}, message {n}");
                    let packet = repo
                        .encrypt("bob:2@s.whatsapp.net", plaintext.as_bytes())
                        .unwrap();
                    (packet, plaintext)
                })
                .collect::<Vec<_>>()
        }));
    }
    let mut packets = Vec::new();
    for worker in workers {
        packets.extend(worker.join().unwrap());
    }
    let mut counters = std::collections::BTreeSet::new();
    for (packet, _) in &packets {
        let wrapper =
            wacore_libsignal::engine::wire::PreKeySignalMessageView::decode(&packet.bytes).unwrap();
        let message =
            wacore_libsignal::engine::wire::SignalMessageView::decode(wrapper.message).unwrap();
        assert!(counters.insert(message.counter));
    }
    assert_eq!(
        counters.into_iter().collect::<Vec<_>>(),
        (0..32).collect::<Vec<_>>()
    );
    for (packet, plaintext) in packets.into_iter().rev() {
        assert_eq!(
            bob.decrypt("alice:1@s.whatsapp.net", packet.kind, &packet.bytes)
                .unwrap()
                .expose(),
            plaintext.as_bytes()
        );
    }
}

#[test]
fn already_established_prekey_session_survives_local_signed_key_rotation() {
    use rustleys_whatsapp::{
        auth::{Bytes, SignedKeyPair},
        crypto,
    };
    let (dir, alice, bob, _a, mut b) = pair(true);
    let first = alice.encrypt("bob:2@s.whatsapp.net", b"first").unwrap();
    let delayed = alice
        .encrypt("bob:2@s.whatsapp.net", b"delayed prekey wrapper")
        .unwrap();
    bob.decrypt("alice:1@s.whatsapp.net", first.kind, &first.bytes)
        .unwrap();
    drop(bob);
    let identity = b.signed_identity_key.private_key().unwrap();
    let signed = crypto::signed_key_pair(&identity, 2).unwrap();
    b.signed_pre_key = SignedKeyPair {
        key_pair: KeyPair::from_private(&signed.private_key),
        signature: Bytes::new(signed.signature.to_vec()),
        key_id: 2,
        timestamp_s: None,
    };
    let restored = Repository::new(
        &b,
        SqliteStore::open(dir.path().join("bob.sqlite")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        restored
            .decrypt("alice:1@s.whatsapp.net", delayed.kind, &delayed.bytes)
            .unwrap()
            .expose(),
        b"delayed prekey wrapper"
    );
}
#[test]
fn changed_identity_is_committed_only_after_a_valid_new_handshake() {
    let (dir, alice, bob, _a, b) = pair(false);
    let first = alice
        .encrypt("bob:2@s.whatsapp.net", b"original identity")
        .unwrap();
    bob.decrypt("alice:1@s.whatsapp.net", first.kind, &first.bytes)
        .unwrap();
    let old = bob.session_info("alice:1@s.whatsapp.net").unwrap().unwrap();
    let changed_creds = Credentials::generate().unwrap();
    let changed = Repository::new(
        &changed_creds,
        SqliteStore::open(dir.path().join("changed.sqlite")).unwrap(),
    )
    .unwrap();
    changed
        .inject_session(
            "bob:2@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let replacement = changed
        .encrypt("bob:2@s.whatsapp.net", b"replacement identity")
        .unwrap();
    let mut forged = replacement.bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(
        bob.decrypt("alice:1@s.whatsapp.net", replacement.kind, &forged)
            .is_err()
    );
    assert_eq!(
        bob.session_info("alice:1@s.whatsapp.net").unwrap().unwrap(),
        old
    );
    let still_original = alice
        .encrypt("bob:2@s.whatsapp.net", b"still original")
        .unwrap();
    assert_eq!(
        bob.decrypt(
            "alice:1@s.whatsapp.net",
            still_original.kind,
            &still_original.bytes
        )
        .unwrap()
        .expose(),
        b"still original"
    );
    assert_eq!(
        bob.decrypt(
            "alice:1@s.whatsapp.net",
            replacement.kind,
            &replacement.bytes
        )
        .unwrap()
        .expose(),
        b"replacement identity"
    );
    assert_ne!(
        bob.session_info("alice:1@s.whatsapp.net")
            .unwrap()
            .unwrap()
            .base_key,
        old.base_key
    );
}

#[test]
fn protocol_addresses_match_original_baileys_repository_helper() {
    let f: Value =
        serde_json::from_str(include_str!("fixtures/signal-address-upstream.json")).unwrap();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    for row in f["cases"].as_array().unwrap() {
        let actual = signal::protocol_address(row["jid"].as_str().unwrap());
        if row["error"] == true {
            assert!(actual.is_err(), "{}", row["jid"]);
        } else {
            assert_eq!(actual.unwrap(), row["address"].as_str().unwrap());
        }
    }
}

#[test]
fn legacy_omitted_zero_prekey_id_is_authenticated_then_consumed_without_downgrading_absence() {
    use wacore_libsignal::engine::wire;
    let directory = tempfile::tempdir().unwrap();
    let alice_creds = Credentials::generate().unwrap();
    let bob_creds = Credentials::generate().unwrap();
    let alice = Repository::new(
        &alice_creds,
        SqliteStore::open(directory.path().join("zero-a.sqlite")).unwrap(),
    )
    .unwrap();
    let bob_store = Arc::new(SqliteStore::open(directory.path().join("zero-b.sqlite")).unwrap());
    let bob = Repository::new(&bob_creds, bob_store.clone()).unwrap();
    let key = KeyPair::generate().unwrap();
    bob.put_pre_key(0, &key).unwrap();
    alice
        .inject_session(
            "bob:1@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&bob_creds, Some((0, &key))).unwrap(),
        )
        .unwrap();
    let packet = alice
        .encrypt("bob:1@s.whatsapp.net", b"legacy zero")
        .unwrap();
    let mut outer = wire::PreKeySignalMessageView::decode(&packet.bytes)
        .unwrap()
        .to_owned();
    outer.pre_key_id = None;
    let omitted = outer.encode();
    let mut damaged = omitted.clone();
    let inner = wire::PreKeySignalMessageView::decode(&damaged)
        .unwrap()
        .message;
    let start = inner.as_ptr() as usize - damaged.as_ptr() as usize;
    let last = start + inner.len() - 1;
    damaged[last] ^= 1;
    assert!(
        bob.decrypt("alice:1@s.whatsapp.net", MessageType::PreKey, &damaged)
            .is_err()
    );
    assert!(bob.has_pre_key(0).unwrap());
    assert!(
        bob.session_info("alice:1@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        bob.decrypt("alice:1@s.whatsapp.net", MessageType::PreKey, &omitted)
            .unwrap()
            .expose(),
        b"legacy zero"
    );
    assert!(!bob.has_pre_key(0).unwrap());
    assert!(
        bob.decrypt("alice:1@s.whatsapp.net", MessageType::PreKey, &omitted)
            .is_err()
    );
    let fail_path = directory.path().join("zero-fail.sqlite");
    let failed = Repository::new(&bob_creds, SqliteStore::open(&fail_path).unwrap()).unwrap();
    failed.put_pre_key(0, &key).unwrap();
    let guard = rusqlite::Connection::open(&fail_path).unwrap();
    guard.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER zero_commit_fail AFTER DELETE ON rustleys_signal_keys WHEN OLD.category='pre-key' AND OLD.id='0' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        failed.decrypt("alice:1@s.whatsapp.net", MessageType::PreKey, &omitted),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    assert!(failed.has_pre_key(0).unwrap());
    assert!(
        failed
            .session_info("alice:1@s.whatsapp.net")
            .unwrap()
            .is_none()
    );
    guard
        .execute_batch("DROP TRIGGER zero_commit_fail")
        .unwrap();
    assert_eq!(
        failed
            .decrypt("alice:1@s.whatsapp.net", MessageType::PreKey, &omitted)
            .unwrap()
            .expose(),
        b"legacy zero"
    );
    assert!(!failed.has_pre_key(0).unwrap());
    // A genuine absent-prekey handshake must succeed as 3DH even when key zero
    // exists locally. It must never consume that unrelated private key.
    let other_creds = Credentials::generate().unwrap();
    let other = Repository::new(
        &other_creds,
        SqliteStore::open(directory.path().join("no-otk.sqlite")).unwrap(),
    )
    .unwrap();
    bob.put_pre_key(0, &key).unwrap();
    other
        .inject_session(
            "bob:1@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&bob_creds, None).unwrap(),
        )
        .unwrap();
    let plain = other
        .encrypt("bob:1@s.whatsapp.net", b"actually absent")
        .unwrap();
    assert_eq!(
        bob.decrypt("other:1@s.whatsapp.net", plain.kind, &plain.bytes)
            .unwrap()
            .expose(),
        b"actually absent"
    );
    assert!(bob.has_pre_key(0).unwrap());
}
