use rustleys_whatsapp::{
    auth::Credentials,
    signal::{self, MessageType, Repository, SqliteStore, Store},
};
use serde_json::{Value, json};
use std::sync::Arc;
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/legacy-sessions-upstream.json")).unwrap()
}
fn record(row: &Value) -> Vec<u8> {
    serde_json::to_vec(&row["record"]).unwrap()
}
fn credentials(row: &Value) -> Credentials {
    Credentials::from_json(row["credentials"].as_str().unwrap().as_bytes()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::from_value(v.clone()).unwrap()
}
const JID: &str = "legacy-peer:2@s.whatsapp.net";
fn repo(
    row: &Value,
) -> (
    tempfile::TempDir,
    Arc<SqliteStore>,
    Repository<Arc<SqliteStore>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("test.sqlite")).unwrap());
    let repo = Repository::new(&credentials(row), store.clone()).unwrap();
    (dir, store, repo)
}
#[test]
fn original_json_import_preserves_skipped_keys_archives_and_process_reopen() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(f["libsignal_version"], "6.0.0");
    assert_eq!(f["synthetic_data"], true);
    for row in f["cases"].as_array().unwrap() {
        let (dir, store, repository) = repo(row);
        let report = repository.import_legacy_session(JID, &record(row)).unwrap();
        assert_eq!(report.open_sessions, 1);
        assert_eq!(
            report.archived_sessions,
            usize::from(row["mode"].as_str().unwrap().starts_with("archived"))
        );
        assert!(repository.validate_session(JID).unwrap().exists);
        drop(repository);
        drop(store);
        let repository = Repository::new(
            &credentials(row),
            SqliteStore::open(dir.path().join("test.sqlite")).unwrap(),
        )
        .unwrap();
        for packet in row["incoming"].as_array().unwrap() {
            let kind = if packet["type"] == "pkmsg" {
                MessageType::PreKey
            } else {
                MessageType::Normal
            };
            assert_eq!(
                repository
                    .decrypt(JID, kind, &bytes(&packet["ciphertext"]))
                    .unwrap()
                    .expose(),
                bytes(&packet["plaintext"])
            );
            assert!(
                repository
                    .decrypt(JID, kind, &bytes(&packet["ciphertext"]))
                    .is_err()
            );
        }
        assert!(matches!(
            repository.import_legacy_session(JID, &record(row)),
            Err(signal::Error::SessionImportConflict)
        ));
    }
}
#[test]
fn legacy_version_zero_registration_fallback_and_empty_records() {
    let f = fixture();
    let row = &f["cases"][0];
    let (_, _, repository) = repo(row);
    let mut v = row["record"].clone();
    v.as_object_mut().unwrap().remove("version");
    let entries = v["_sessions"].as_object_mut().unwrap();
    let entry = entries.values_mut().next().unwrap();
    let reg = entry
        .as_object_mut()
        .unwrap()
        .remove("registrationId")
        .unwrap();
    v["registrationId"] = reg;
    repository
        .import_legacy_session(JID, &serde_json::to_vec(&v).unwrap())
        .unwrap();
    let (_, _, empty) = repo(row);
    let report = empty
        .import_legacy_session(JID, b"{\"version\":\"v1\",\"_sessions\":{}}")
        .unwrap();
    assert_eq!(report.open_sessions, 0);
    assert!(!empty.validate_session(JID).unwrap().exists);
}
#[test]
fn malformed_keys_counters_and_duplicate_rows_never_persist() {
    let f = fixture();
    let row = &f["cases"][2];
    for change in 0..11 {
        let (_, store, repository) = repo(row);
        let mut v = row["record"].clone();
        let entry = v["_sessions"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        match change {
            0 => entry["currentRatchet"]["rootKey"] = json!("not a key"),
            1 => {
                entry["currentRatchet"]["ephemeralKeyPair"]["privKey"] =
                    json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            }
            2 => entry["currentRatchet"]["previousCounter"] = json!(-2),
            3 => entry["indexInfo"]["closed"] = json!(-2),
            4 => entry["indexInfo"]["baseKeyType"] = json!(3),
            5 => entry["extraUnknownState"] = json!("must not be silently lost"),
            6 => {
                entry["_chains"]
                    .as_object_mut()
                    .unwrap()
                    .values_mut()
                    .next()
                    .unwrap()["chainKey"]["counter"] = json!(-2)
            }
            7 => {
                entry["_chains"]
                    .as_object_mut()
                    .unwrap()
                    .values_mut()
                    .next()
                    .unwrap()["chainKey"]["counter"] = json!(4294967295_u64)
            }
            8 => {
                entry["_chains"]
                    .as_object_mut()
                    .unwrap()
                    .values_mut()
                    .next()
                    .unwrap()["chainType"] = json!(8)
            }
            9 => {
                entry["_chains"]
                    .as_object_mut()
                    .unwrap()
                    .values_mut()
                    .next()
                    .unwrap()["messageKeys"] =
                    json!({"000":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
            }
            _ => v["version"] = json!("v2"),
        }
        let error = repository
            .import_legacy_session(JID, &serde_json::to_vec(&v).unwrap())
            .unwrap_err();
        assert!(!format!("{error:?}").contains("not a key"));
        assert!(
            store
                .transaction(|tx| tx.get("session", "legacy-peer.2"))
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .transaction(|tx| tx.get("identity-key", "legacy-peer.2"))
                .unwrap()
                .is_none()
        );
    }
    let (_, _, repository) = repo(row);
    assert!(
        repository
            .import_legacy_session(
                JID,
                b"{\"version\":\"v1\",\"_sessions\":{},\"_sessions\":{}}"
            )
            .is_err()
    );
    let duplicate = record(row);
    let source = String::from_utf8(duplicate).unwrap();
    let key = source
        .split("\"_sessions\":{")
        .nth(1)
        .unwrap()
        .split(':')
        .next()
        .unwrap();
    // Duplicate a real session entry in the raw JSON map, before serde can overwrite it.
    let entries = row["record"]["_sessions"].as_object().unwrap();
    let value = serde_json::to_string(entries.values().next().unwrap()).unwrap();
    let duplicate = format!("{{\"version\":\"v1\",\"_sessions\":{{{key}:{value},{key}:{value}}}}}");
    assert!(
        repository
            .import_legacy_session(JID, duplicate.as_bytes())
            .is_err()
    );
}
#[test]
fn commit_failure_and_conflicting_identity_do_not_partially_import() {
    let f = fixture();
    let row = &f["cases"][0];
    let (_, store, repository) = repo(row);
    store
        .transaction(|tx| tx.put("identity-key", "legacy-peer.2", &[19; 32]))
        .unwrap();
    assert!(matches!(
        repository.import_legacy_session(JID, &record(row)),
        Err(signal::Error::SessionImportConflict)
    ));
    assert!(
        store
            .transaction(|tx| tx.get("session", "legacy-peer.2"))
            .unwrap()
            .is_none()
    );
    // Construct against the normal store so account binding is already durable.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(dir.path().join("fail.sqlite")).unwrap());
    let _ = Repository::new(&credentials(row), store.clone()).unwrap();
    // This backend needs account binding during Repository::new too, so switch its failure with an atomic flag.
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Switch {
        store: Arc<SqliteStore>,
        fail: Arc<AtomicBool>,
    }
    impl Store for Switch {
        fn transaction<T>(
            &self,
            work: impl FnOnce(&mut dyn signal::Transaction) -> signal::Result<T>,
        ) -> signal::Result<T> {
            self.store.transaction(|tx| {
                let value = work(tx)?;
                if self.fail.load(Ordering::SeqCst) {
                    Err(signal::Error::Storage)
                } else {
                    Ok(value)
                }
            })
        }
    }
    let fail = Arc::new(AtomicBool::new(false));
    let repository = Repository::new(
        &credentials(row),
        Switch {
            store: store.clone(),
            fail: fail.clone(),
        },
    )
    .unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(repository.import_legacy_session(JID, &record(row)).is_err());
    for category in ["session", "identity-key"] {
        assert!(
            store
                .transaction(|tx| tx.get(category, "legacy-peer.2"))
                .unwrap()
                .is_none()
        );
    }
    fail.store(false, Ordering::SeqCst);
    repository.import_legacy_session(JID, &record(row)).unwrap();
}

#[test]
fn archived_messages_do_not_replace_the_open_session_or_reopen_a_closed_record() {
    let f = fixture();
    for row in f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["mode"].as_str().unwrap().starts_with("archived"))
    {
        for closed_only in [false, true] {
            let (_, _, repository) = repo(row);
            let mut value = row["record"].clone();
            if closed_only {
                value["_sessions"]
                    .as_object_mut()
                    .unwrap()
                    .retain(|_, entry| entry["indexInfo"]["closed"] != -1);
            }
            repository
                .import_legacy_session(JID, &serde_json::to_vec(&value).unwrap())
                .unwrap();
            let before = repository.session_info(JID).unwrap();
            let packet = row["incoming"].as_array().unwrap().last().unwrap();
            let kind = if packet["type"] == "pkmsg" {
                MessageType::PreKey
            } else {
                MessageType::Normal
            };
            assert_eq!(
                repository
                    .decrypt(JID, kind, &bytes(&packet["ciphertext"]))
                    .unwrap()
                    .expose(),
                bytes(&packet["plaintext"])
            );
            assert_eq!(repository.session_info(JID).unwrap(), before);
            assert_eq!(
                repository.validate_session(JID).unwrap().exists,
                !closed_only
            );
            assert!(
                repository
                    .decrypt(JID, kind, &bytes(&packet["ciphertext"]))
                    .is_err()
            );
        }
    }
}
#[test]
fn ambiguous_open_sessions_unknown_versions_and_size_limits_are_rejected() {
    let f = fixture();
    let row = &f["cases"][6];
    let (_, _, repository) = repo(row);
    let mut record = row["record"].clone();
    for entry in record["_sessions"].as_object_mut().unwrap().values_mut() {
        entry["indexInfo"]["closed"] = json!(-1);
    }
    assert!(
        repository
            .import_legacy_session(JID, &serde_json::to_vec(&record).unwrap())
            .is_err()
    );
    let oversized = vec![b' '; rustleys_whatsapp::legacy_session::MAX_LEGACY_SESSION_BYTES + 1];
    assert!(matches!(
        repository.import_legacy_session(JID, &oversized),
        Err(signal::Error::TooLarge)
    ));
    let mut record = row["record"].clone();
    let entry = record["_sessions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    let chain = entry["_chains"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .find(|c| c["chainType"] == 2)
        .unwrap();
    chain["chainKey"]["counter"] = json!(40000);
    let map = (0..32769)
        .map(|index| {
            (
                index.to_string(),
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    chain["messageKeys"] = Value::Object(map);
    assert!(matches!(
        repository.import_legacy_session(JID, &serde_json::to_vec(&record).unwrap()),
        Err(signal::Error::TooLarge)
    ));
}
#[test]
fn deferred_sqlite_commit_failure_rolls_back_identity_and_session() {
    let f = fixture();
    let row = &f["cases"][0];
    let (dir, store, repository) = repo(row);
    let connection = rusqlite::Connection::open(dir.path().join("test.sqlite")).unwrap();
    connection.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY); CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_import AFTER INSERT ON rustleys_signal_keys WHEN NEW.category='session' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        repository.import_legacy_session(JID, &record(row)),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    for category in ["identity-key", "session"] {
        assert!(
            store
                .transaction(|tx| tx.get(category, "legacy-peer.2"))
                .unwrap()
                .is_none()
        );
    }
    connection
        .execute_batch("DROP TRIGGER fail_import")
        .unwrap();
    repository.import_legacy_session(JID, &record(row)).unwrap();
}
#[test]
fn imports_resolve_committed_aliases_without_overwriting_either_address() {
    use rustleys_whatsapp::lid_mapping::{LidMappingStore, Mapping};
    let f = fixture();
    let row = &f["cases"][0];
    let (_, store, repository) = repo(row);
    LidMappingStore::new(store.clone())
        .store_mappings(&[Mapping {
            pn: "legacy-peer@s.whatsapp.net".into(),
            lid: "legacy-lid@lid".into(),
        }])
        .unwrap();
    repository.import_legacy_session(JID, &record(row)).unwrap();
    assert!(
        repository
            .validate_session("legacy-lid:2@lid")
            .unwrap()
            .exists
    );
    assert!(
        store
            .transaction(|tx| tx.get("session", "legacy-peer.2"))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .transaction(|tx| tx.get("session", "legacy-lid_1.2"))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        repository.import_legacy_session("legacy-lid:2@lid", &record(row)),
        Err(signal::Error::SessionImportConflict)
    ));
}

#[test]
fn already_corrupted_original_archive_fails_without_mutating_imported_state() {
    let row: Value =
        serde_json::from_str(include_str!("fixtures/legacy-archive-regression.json")).unwrap();
    assert_eq!(row["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(row["synthetic_data"], true);
    let (_, store, repository) = repo(&row);
    repository
        .import_legacy_session(JID, &record(&row))
        .unwrap();
    let packets = row["incoming"].as_array().unwrap();
    for packet in &packets[..3] {
        repository
            .decrypt(JID, MessageType::Normal, &bytes(&packet["ciphertext"]))
            .unwrap();
    }
    let before = store
        .transaction(|tx| tx.get("session", "legacy-peer.2"))
        .unwrap()
        .unwrap();
    assert!(
        repository
            .decrypt(JID, MessageType::Normal, &bytes(&packets[3]["ciphertext"]))
            .is_err()
    );
    let after = store
        .transaction(|tx| tx.get("session", "legacy-peer.2"))
        .unwrap()
        .unwrap();
    assert_eq!(*before, *after);
}
