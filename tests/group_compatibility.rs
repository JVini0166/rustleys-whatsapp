use rustleys_whatsapp::{
    auth::Credentials,
    group_signal::sender_key_name,
    signal::{self, Repository, SqliteStore, Store},
};
use serde_json::Value;
use std::sync::Arc;
use wacore_libsignal::engine::{codec, wire};
const GROUP: &str = "synthetic@g.us";
const AUTHOR: &str = "synthetic-sender:1@s.whatsapp.net";
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/group-upstream.json")).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect()
}
fn repo(
    path: impl AsRef<std::path::Path>,
) -> (Credentials, Arc<SqliteStore>, Repository<Arc<SqliteStore>>) {
    let creds = Credentials::generate().unwrap();
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let repo = Repository::new(&creds, store.clone()).unwrap();
    (creds, store, repo)
}
#[test]
fn original_group_messages_decrypt_out_of_order_and_across_restarts() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(f["synthetic_data"], true);
    for case in f["cases"].as_array().unwrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receiver.sqlite");
        let (creds, _, receiver) = repo(&path);
        let group = case["group"].as_str().unwrap();
        let author = case["author"].as_str().unwrap();
        assert_eq!(sender_key_name(group, author).unwrap(), case["name"]);
        receiver
            .process_sender_key_distribution(group, author, &bytes(&case["distribution"]))
            .unwrap();
        for index in [7, 0, 6, 1, 5, 2, 4, 3] {
            let reopened = Repository::new(&creds, SqliteStore::open(&path).unwrap()).unwrap();
            let row = &case["packets"][index];
            assert_eq!(
                reopened
                    .decrypt_group_message(group, author, &bytes(&row["ciphertext"]))
                    .unwrap()
                    .expose(),
                bytes(&row["plaintext"])
            );
        }
        assert_eq!(
            case["legacy_storage_reordering_error"],
            "Expected Buffer instead of: Object"
        );
        let first = bytes(&case["packets"][0]["ciphertext"]);
        assert!(
            receiver
                .decrypt_group_message(group, author, &first)
                .is_err()
        );
        receiver
            .process_sender_key_distribution(group, author, &bytes(&case["distribution"]))
            .unwrap();
        assert!(
            receiver
                .decrypt_group_message(group, author, &first)
                .is_err()
        );
    }
}
#[test]
fn native_group_sender_preserves_original_counter_progression_for_multiple_receivers() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, _, a) = repo(dir.path().join("a.sqlite"));
    let (_, _, b) = repo(dir.path().join("b.sqlite"));
    assert!(!sender.has_sender_key(GROUP, AUTHOR).unwrap());
    let initial = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    assert!(sender.has_sender_key(GROUP, AUTHOR).unwrap());
    let key = wire::SenderKeyDistribution::decode(initial.expose()).unwrap();
    assert!(key.id < 0x7fff_ffff);
    a.process_sender_key_distribution(GROUP, AUTHOR, initial.expose())
        .unwrap();
    b.process_sender_key_distribution(GROUP, AUTHOR, initial.expose())
        .unwrap();
    let mut messages = Vec::new();
    for n in 0..8 {
        let plaintext = vec![n as u8; 17 * n];
        let encrypted = sender
            .encrypt_group_message(GROUP, AUTHOR, &plaintext)
            .unwrap();
        let parsed = wire::SenderKeyMessage::decode(&encrypted.ciphertext).unwrap();
        assert_eq!(parsed.iteration, (n * 2) as u32);
        assert_eq!(parsed.id, key.id);
        // Repeated distributions must not replace consumed state or skipped keys.
        a.process_sender_key_distribution(
            GROUP,
            AUTHOR,
            encrypted.sender_key_distribution.expose(),
        )
        .unwrap();
        messages.push((encrypted, plaintext));
    }
    for index in [7, 0, 6, 1, 5, 2, 4, 3] {
        let (encrypted, plaintext) = &messages[index];
        assert_eq!(
            a.decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext)
                .unwrap()
                .expose(),
            plaintext
        );
        assert_eq!(
            b.decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext)
                .unwrap()
                .expose(),
            plaintext
        );
    }
    assert!(
        a.decrypt_group_message(GROUP, AUTHOR, &messages[0].0.ciphertext)
            .is_err()
    );
}
#[test]
fn signatures_bad_frames_and_wrong_names_do_not_advance_receiver_state() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, store, receiver) = repo(dir.path().join("receiver.sqlite"));
    let encrypted = sender
        .encrypt_group_message(GROUP, AUTHOR, b"synthetic plaintext")
        .unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, encrypted.sender_key_distribution.expose())
        .unwrap();
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let before = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    let mut corrupt = encrypted.ciphertext.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &corrupt)
            .is_err()
    );
    for n in [0, 1, 3, 16, 63, 64] {
        assert!(
            receiver
                .decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext[..n])
                .is_err()
        );
    }
    assert!(
        receiver
            .decrypt_group_message("other@g.us", AUTHOR, &encrypted.ciphertext)
            .is_err()
    );
    assert!(
        receiver
            .decrypt_group_message(GROUP, "other:1@s.whatsapp.net", &encrypted.ciphertext)
            .is_err()
    );
    let after = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert_eq!(before.as_slice(), after.as_slice());
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext)
            .unwrap()
            .expose(),
        b"synthetic plaintext"
    );
}
#[test]
fn distribution_creation_and_group_encryption_are_not_published_on_commit_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sender.sqlite");
    let (_, _, sender) = repo(&path);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_group_insert AFTER INSERT ON rustleys_signal_keys WHEN NEW.category='sender-key' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        sender.sender_key_distribution(GROUP, AUTHOR),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    assert!(!sender.has_sender_key(GROUP, AUTHOR).unwrap());
    assert!(matches!(
        sender.encrypt_group_message(GROUP, AUTHOR, b"not returned"),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    assert!(!sender.has_sender_key(GROUP, AUTHOR).unwrap());
    conn.execute_batch("DROP TRIGGER fail_group_insert;")
        .unwrap();
    let first = sender
        .encrypt_group_message(GROUP, AUTHOR, b"after retry")
        .unwrap();
    assert_eq!(
        wire::SenderKeyMessage::decode(&first.ciphertext)
            .unwrap()
            .iteration,
        0
    );
    conn.execute_batch("CREATE TRIGGER fail_group_update AFTER UPDATE ON rustleys_signal_keys WHEN NEW.category='sender-key' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        sender.encrypt_group_message(GROUP, AUTHOR, b"failed existing chain"),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    conn.execute_batch("DROP TRIGGER fail_group_update;")
        .unwrap();
    let retry = sender
        .encrypt_group_message(GROUP, AUTHOR, b"second after retry")
        .unwrap();
    assert_eq!(
        wire::SenderKeyMessage::decode(&retry.ciphertext)
            .unwrap()
            .iteration,
        2
    );
}
#[test]
fn failed_decryption_commit_keeps_the_message_key_available_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receiver.sqlite");
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (creds, store, receiver) = repo(&path);
    let encrypted = sender
        .encrypt_group_message(GROUP, AUTHOR, b"atomic receive")
        .unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, encrypted.sender_key_distribution.expose())
        .unwrap();
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let before = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_group_update AFTER UPDATE ON rustleys_signal_keys WHEN NEW.category='sender-key' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        receiver.decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    let after = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert_eq!(before.as_slice(), after.as_slice());
    conn.execute_batch("DROP TRIGGER fail_group_update;")
        .unwrap();
    drop(receiver);
    drop(store);
    let reopened = Repository::new(&creds, SqliteStore::open(path).unwrap()).unwrap();
    assert_eq!(
        reopened
            .decrypt_group_message(GROUP, AUTHOR, &encrypted.ciphertext)
            .unwrap()
            .expose(),
        b"atomic receive"
    );
}
#[test]
fn rotation_retains_five_states_and_late_joiners_only_receive_future_messages() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, store, receiver) = repo(dir.path().join("receiver.sqlite"));
    let mut packets = Vec::new();
    for n in 0..6 {
        sender.delete_sender_key(GROUP, AUTHOR).unwrap();
        let packet = sender.encrypt_group_message(GROUP, AUTHOR, &[n]).unwrap();
        receiver
            .process_sender_key_distribution(GROUP, AUTHOR, packet.sender_key_distribution.expose())
            .unwrap();
        packets.push(packet);
    }
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let snapshot = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_sender_key_record(&wacore_libsignal::engine::RustCrypto, &snapshot)
            .unwrap()
            .states
            .len(),
        5
    );
    assert!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &packets[0].ciphertext)
            .is_err()
    );
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &packets[1].ciphertext)
            .unwrap()
            .expose(),
        [1]
    );
    let (_, _, late) = repo(dir.path().join("late.sqlite"));
    let distribution = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    late.process_sender_key_distribution(GROUP, AUTHOR, distribution.expose())
        .unwrap();
    let future = sender
        .encrypt_group_message(GROUP, AUTHOR, b"future")
        .unwrap();
    assert_eq!(
        late.decrypt_group_message(GROUP, AUTHOR, &future.ciphertext)
            .unwrap()
            .expose(),
        b"future"
    );
    assert!(
        late.decrypt_group_message(GROUP, AUTHOR, &packets[5].ciphertext)
            .is_err()
    );
}
#[test]
fn authenticated_future_gap_and_counter_exhaustion_fail_without_mutating_state() {
    use wacore_libsignal::engine::RustCrypto;
    let dir = tempfile::tempdir().unwrap();
    let (_, store, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, _, receiver) = repo(dir.path().join("receiver.sqlite"));
    let distribution = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, distribution.expose())
        .unwrap();
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let data = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    let mut record = codec::decode_sender_key_record(&RustCrypto, &data).unwrap();
    let state = &record.states[0];
    let private = rustleys_whatsapp::crypto::PrivateKey::from_bytes(state.signing_private.unwrap());
    let mut message = wire::SenderKeyMessage {
        id: state.id,
        iteration: 2001,
        ciphertext: vec![0; 16],
        signature: [0; 64],
    };
    message.signature = private.sign(&message.unsigned()).unwrap();
    assert!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &message.encode())
            .is_err()
    );
    record.states[0].iteration = u32::MAX;
    let bytes = zeroize::Zeroizing::new(codec::encode_sender_key_record(&record));
    store
        .transaction(|tx| tx.put("sender-key", &name, &bytes))
        .unwrap();
    assert!(
        sender
            .encrypt_group_message(GROUP, AUTHOR, b"overflow")
            .is_err()
    );
    let after = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert_eq!(bytes.as_slice(), after.as_slice());
}
#[test]
fn invalid_distributions_and_receive_only_keys_cannot_replace_sending_material() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, _, receiver) = repo(dir.path().join("receiver.sqlite"));
    let distribution = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, distribution.expose())
        .unwrap();
    assert!(
        receiver
            .encrypt_group_message(GROUP, AUTHOR, b"no private signing key")
            .is_err()
    );
    let before = receiver.sender_key_distribution(GROUP, AUTHOR).unwrap();
    assert_eq!(before.expose(), distribution.expose());
    for input in [
        vec![],
        vec![0x33],
        vec![0, 0, 0],
        distribution.expose()[..10].to_vec(),
    ] {
        assert!(
            receiver
                .process_sender_key_distribution(GROUP, AUTHOR, &input)
                .is_err()
        );
    }
    assert_eq!(
        receiver
            .sender_key_distribution(GROUP, AUTHOR)
            .unwrap()
            .expose(),
        distribution.expose()
    );
    assert!(sender_key_name("", AUTHOR).is_err());
    assert!(sender_key_name(GROUP, "invalid").is_err());
}

#[test]
fn sender_key_names_equal_and_hash_like_original_including_utf16() {
    use rustleys_whatsapp::group_signal::SenderKeyName;
    let f = fixture();
    for row in f["names"].as_array().unwrap() {
        let name = SenderKeyName::new(
            row["group"].as_str().unwrap(),
            row["sender"].as_str().unwrap(),
            row["device"].as_u64().unwrap() as u32,
        );
        assert_eq!(name.serialize(), row["serialized"]);
        assert_eq!(name.hash_code(), row["hash"].as_i64().unwrap() as i32);
        assert!(name.equals(Some(&name.clone())));
        assert!(!name.equals(None));
        assert_eq!(name.group_id(), row["group"].as_str().unwrap());
        assert_eq!(name.sender_id(), row["sender"].as_str().unwrap());
        assert_eq!(name.device_id(), row["device"].as_u64().unwrap() as u32);
    }
}

#[test]
fn fresh_authenticated_distribution_resumes_a_large_gap_without_replaying_consumed_keys() {
    use wacore_libsignal::engine::{CryptoProvider, RustCrypto};
    let dir = tempfile::tempdir().unwrap();
    let (_, store, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, _, receiver) = repo(dir.path().join("receiver.sqlite"));
    let initial = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, initial.expose())
        .unwrap();
    let first = sender
        .encrypt_group_message(GROUP, AUTHOR, b"first")
        .unwrap();
    receiver
        .decrypt_group_message(GROUP, AUTHOR, &first.ciphertext)
        .unwrap();
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let bytes = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    let mut record = codec::decode_sender_key_record(&RustCrypto, &bytes).unwrap();
    while record.states[0].iteration < 5001 {
        let state = &mut record.states[0];
        state.chain_key = RustCrypto.hmac_sha256(&state.chain_key, &[&[2]]).unwrap();
        state.iteration += 1;
    }
    let snapshot = zeroize::Zeroizing::new(codec::encode_sender_key_record(&record));
    store
        .transaction(|tx| tx.put("sender-key", &name, &snapshot))
        .unwrap();
    let refresh = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    let future = sender
        .encrypt_group_message(GROUP, AUTHOR, b"after a large gap")
        .unwrap();
    assert!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &future.ciphertext)
            .is_err()
    );
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, refresh.expose())
        .unwrap();
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &future.ciphertext)
            .unwrap()
            .expose(),
        b"after a large gap"
    );
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, initial.expose())
        .unwrap();
    assert!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &first.ciphertext)
            .is_err()
    );
}
#[test]
fn in_window_distribution_refresh_preserves_skipped_keys_and_rejects_wrong_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, store, receiver) = repo(dir.path().join("receiver.sqlite"));
    let initial = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, initial.expose())
        .unwrap();
    let first = sender
        .encrypt_group_message(GROUP, AUTHOR, b"delayed")
        .unwrap();
    let second = sender
        .encrypt_group_message(GROUP, AUTHOR, b"newer")
        .unwrap();
    let refresh = sender.sender_key_distribution(GROUP, AUTHOR).unwrap();
    let mut invalid = wire::SenderKeyDistribution::decode(refresh.expose()).unwrap();
    invalid.chain_key[0] ^= 1;
    let name = sender_key_name(GROUP, AUTHOR).unwrap();
    let before = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert!(
        receiver
            .process_sender_key_distribution(GROUP, AUTHOR, &invalid.encode())
            .is_err()
    );
    let after = store
        .transaction(|tx| tx.get("sender-key", &name))
        .unwrap()
        .unwrap();
    assert_eq!(before.as_slice(), after.as_slice());
    receiver
        .process_sender_key_distribution(GROUP, AUTHOR, refresh.expose())
        .unwrap();
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &second.ciphertext)
            .unwrap()
            .expose(),
        b"newer"
    );
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &first.ciphertext)
            .unwrap()
            .expose(),
        b"delayed"
    );
}

#[test]
fn typed_distribution_message_validates_and_connects_protobuf_to_group_repository() {
    use prost::Message;
    use rustleys_whatsapp::proto::message::SenderKeyDistributionMessage;
    let dir = tempfile::tempdir().unwrap();
    let (_, _, sender) = repo(dir.path().join("sender.sqlite"));
    let (_, _, receiver) = repo(dir.path().join("receiver.sqlite"));
    let packet = sender
        .encrypt_group_message(GROUP, AUTHOR, b"typed protobuf flow")
        .unwrap();
    let message = packet.distribution_message(GROUP).unwrap();
    let decoded = SenderKeyDistributionMessage::decode(message.encode_to_vec().as_slice()).unwrap();
    receiver
        .process_sender_key_distribution_message(&decoded, AUTHOR)
        .unwrap();
    assert_eq!(
        receiver
            .decrypt_group_message(GROUP, AUTHOR, &packet.ciphertext)
            .unwrap()
            .expose(),
        b"typed protobuf flow"
    );
    assert!(packet.distribution_message("").is_err());
    assert!(
        receiver
            .process_sender_key_distribution_message(
                &SenderKeyDistributionMessage::default(),
                AUTHOR
            )
            .is_err()
    );
    let missing = SenderKeyDistributionMessage {
        group_id: Some(GROUP.into()),
        ..Default::default()
    };
    assert!(
        receiver
            .process_sender_key_distribution_message(&missing, AUTHOR)
            .is_err()
    );
}
