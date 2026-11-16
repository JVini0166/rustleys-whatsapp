use rustleys_whatsapp::{
    auth::Credentials,
    lid_mapping::LidMappingStore,
    session_migration::MigrationReport,
    signal::{self, PreKeyBundle, Repository, SqliteStore, Store},
};
use std::sync::Arc;
use wacore_libsignal::engine::{self, RustCrypto, codec, wire};
fn repo(
    path: impl AsRef<std::path::Path>,
    creds: &Credentials,
) -> (Arc<SqliteStore>, Repository<Arc<SqliteStore>>) {
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let repo = Repository::new(creds, store.clone()).unwrap();
    (store, repo)
}
fn counter(packet: &signal::Ciphertext) -> u32 {
    let outer = wire::PreKeySignalMessageView::decode(&packet.bytes).unwrap();
    wire::SignalMessageView::decode(outer.message)
        .unwrap()
        .counter
}
fn get(store: &Arc<SqliteStore>, category: &str, id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    store.transaction(|tx| tx.get(category, id)).unwrap()
}
#[test]
fn multiple_devices_move_atomically_and_pn_lid_share_the_same_live_session() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    let (_, bob) = repo(dir.path().join("b.sqlite"), &b);
    let bundle = PreKeyBundle::from_credentials(&b, None).unwrap();
    alice.inject_session("pnA@s.whatsapp.net", &bundle).unwrap();
    alice
        .inject_session("pnA:2@s.whatsapp.net", &bundle)
        .unwrap();
    alice
        .set_device_list("pnA@s.whatsapp.net", &[0, 2])
        .unwrap();
    let first = alice.session_info("pnA@s.whatsapp.net").unwrap().unwrap();
    let second = alice.session_info("pnA:2@s.whatsapp.net").unwrap().unwrap();
    let report = alice
        .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
        .unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/lid-upstream.json")).unwrap();
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        fixture["migration_common"]
    );
    assert_eq!(
        alice.session_info("pnA@s.whatsapp.net").unwrap().unwrap(),
        first
    );
    assert_eq!(alice.session_info("lidA:2@lid").unwrap().unwrap(), second);
    assert!(get(&store, "session", "pnA.0").is_none());
    assert!(get(&store, "session", "pnA.2").is_none());
    assert!(get(&store, "identity-key", "lidA_1.2").is_some());
    assert!(alice.validate_session("pnA@s.whatsapp.net").unwrap().exists);
    let packet = alice
        .encrypt("pnA@s.whatsapp.net", b"after migration")
        .unwrap();
    assert_eq!(
        bob.decrypt("local:1@s.whatsapp.net", packet.kind, &packet.bytes)
            .unwrap()
            .expose(),
        b"after migration"
    );
    let reply = bob.encrypt("local:1@s.whatsapp.net", b"reply").unwrap();
    assert_eq!(
        alice
            .decrypt("lidA@lid", reply.kind, &reply.bytes)
            .unwrap()
            .expose(),
        b"reply"
    );
    let lookup = LidMappingStore::new(store.clone());
    assert_eq!(
        lookup
            .get_lid_for_pn("pnA:2@s.whatsapp.net")
            .unwrap()
            .as_deref(),
        Some("lidA:2@lid")
    );
    alice
        .delete_sessions(&["pnA:2@s.whatsapp.net".into()])
        .unwrap();
    assert!(!alice.validate_session("lidA:2@lid").unwrap().exists);
}
#[test]
fn hosted_device_99_and_standard_devices_keep_separate_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    let bundle = PreKeyBundle::from_credentials(&b, None).unwrap();
    alice.inject_session("pnA@s.whatsapp.net", &bundle).unwrap();
    alice.inject_session("pnA:99@hosted", &bundle).unwrap();
    alice
        .set_device_list("pnA@s.whatsapp.net", &[0, 99, 99])
        .unwrap();
    let normal = alice.session_info("pnA@s.whatsapp.net").unwrap().unwrap();
    let hosted = alice.session_info("pnA:99@hosted").unwrap().unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA:99@hosted", "lidA:99@hosted.lid")
            .unwrap(),
        MigrationReport {
            migrated: 2,
            skipped: 0,
            total: 2
        }
    );
    assert_eq!(alice.session_info("lidA@lid").unwrap().unwrap(), normal);
    assert_eq!(
        alice.session_info("lidA:99@hosted.lid").unwrap().unwrap(),
        hosted
    );
    assert!(get(&store, "session", "pnA_128.99").is_none());
    assert!(get(&store, "session", "lidA_129.99").is_some());
    assert_eq!(
        alice.session_info("pnA:99@hosted").unwrap().unwrap(),
        hosted
    );
}
#[test]
fn migration_commit_failure_rolls_back_every_device_identity_mapping_and_revision() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let path = dir.path().join("a.sqlite");
    let (store, alice) = repo(&path, &a);
    let bundle = PreKeyBundle::from_credentials(&b, None).unwrap();
    for jid in ["pnA@s.whatsapp.net", "pnA:2@s.whatsapp.net"] {
        alice.inject_session(jid, &bundle).unwrap();
    }
    alice
        .set_device_list("pnA@s.whatsapp.net", &[0, 2])
        .unwrap();
    let before = get(&store, "session", "pnA.0").unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE guard_parent(id INTEGER PRIMARY KEY);CREATE TABLE commit_guard(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_migration AFTER INSERT ON rustleys_signal_keys WHEN NEW.category='lid-mapping' BEGIN INSERT INTO commit_guard VALUES(1); END;").unwrap();
    assert!(matches!(
        alice.migrate_session("pnA@s.whatsapp.net", "lidA@lid"),
        Err(signal::Error::Database {
            operation: "commit",
            ..
        })
    ));
    assert_eq!(
        get(&store, "session", "pnA.0").unwrap().as_slice(),
        before.as_slice()
    );
    assert!(get(&store, "session", "pnA.2").is_some());
    assert!(get(&store, "session", "lidA_1.0").is_none());
    assert!(get(&store, "identity-key", "pnA.0").is_some());
    assert!(get(&store, "identity-key", "lidA_1.0").is_none());
    assert!(get(&store, "lid-mapping", "pnA").is_none());
    assert!(get(&store, "meta", "lid-mapping-revision").is_none());
    conn.execute_batch("DROP TRIGGER fail_migration;").unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .unwrap()
            .migrated,
        2
    );
}
#[test]
fn existing_lid_state_is_never_replaced_by_an_older_pn_sending_chain() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    let (_, bob) = repo(dir.path().join("b.sqlite"), &b);
    alice
        .inject_session(
            "pnA@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let old = get(&store, "session", "pnA.0").unwrap();
    let first = alice
        .encrypt("pnA@s.whatsapp.net", b"already sent")
        .unwrap();
    let newer = get(&store, "session", "pnA.0").unwrap();
    let identity = get(&store, "identity-key", "pnA.0").unwrap();
    store
        .transaction(|tx| {
            tx.put("session", "lidA_1.0", &newer)?;
            tx.put("identity-key", "lidA_1.0", &identity)?;
            tx.put("session", "pnA.0", &old)
        })
        .unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .unwrap(),
        MigrationReport {
            migrated: 0,
            skipped: 1,
            total: 1
        }
    );
    assert!(get(&store, "session", "pnA.0").is_none());
    assert_eq!(
        alice
            .migration_conflict_snapshot("pnA@s.whatsapp.net")
            .unwrap()
            .unwrap()
            .expose(),
        old.as_slice()
    );
    assert_eq!(
        get(&store, "session", "lidA_1.0").unwrap().as_slice(),
        newer.as_slice()
    );
    let second = alice
        .encrypt("pnA@s.whatsapp.net", b"after migration")
        .unwrap();
    assert_eq!(counter(&first), 0);
    assert_eq!(counter(&second), 1);
    assert_eq!(
        bob.decrypt("local:1@s.whatsapp.net", first.kind, &first.bytes)
            .unwrap()
            .expose(),
        b"already sent"
    );
    assert_eq!(
        bob.decrypt("local:1@s.whatsapp.net", second.kind, &second.bytes)
            .unwrap()
            .expose(),
        b"after migration"
    );
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/lid-upstream.json")).unwrap();
    assert_eq!(
        f["differences"]["legacy_counter_before"],
        f["differences"]["legacy_counter_after_migration"]
    );
}
#[test]
fn repeated_migration_does_not_use_a_stale_migrated_device_cache() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    alice
        .inject_session(
            "pnA@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let original = get(&store, "session", "pnA.0").unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .unwrap()
            .migrated,
        1
    );
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .unwrap(),
        MigrationReport::default()
    );
    store
        .transaction(|tx| tx.put("session", "pnA.0", &original))
        .unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .unwrap()
            .total,
        1
    );
    assert!(get(&store, "session", "pnA.0").is_none());
    assert!(
        alice
            .migration_conflict_snapshot("pnA@s.whatsapp.net")
            .unwrap()
            .is_some()
    );
}
#[test]
fn conflicting_identities_and_archived_destinations_are_reported_without_data_loss() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let c = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    alice
        .inject_session(
            "pnA@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    alice
        .inject_session(
            "lidA@lid",
            &PreKeyBundle::from_credentials(&c, None).unwrap(),
        )
        .unwrap();
    let source = get(&store, "session", "pnA.0").unwrap();
    let destination = get(&store, "session", "lidA_1.0").unwrap();
    assert!(matches!(
        alice.migrate_session("pnA@s.whatsapp.net", "lidA@lid"),
        Err(signal::Error::MigrationConflict)
    ));
    assert_eq!(
        get(&store, "session", "pnA.0").unwrap().as_slice(),
        source.as_slice()
    );
    assert_eq!(
        get(&store, "session", "lidA_1.0").unwrap().as_slice(),
        destination.as_slice()
    );
    assert!(get(&store, "lid-mapping", "pnA").is_none());
    let mut archived = codec::decode_session_record(&RustCrypto, &source).unwrap();
    let state = archived.current.clone().unwrap();
    archived.install(state);
    archived.current = None;
    let closed = zeroize::Zeroizing::new(codec::encode_session_record(&archived));
    store
        .transaction(|tx| {
            tx.put("session", "lidA_1.0", &closed)?;
            tx.remove("identity-key", "lidA_1.0")
        })
        .unwrap();
    assert!(!alice.validate_session("lidA@lid").unwrap().exists);
    assert_eq!(
        alice.validate_session("lidA@lid").unwrap().reason,
        Some("no open session")
    );
    assert!(matches!(
        alice.migrate_session("pnA@s.whatsapp.net", "lidA@lid"),
        Err(signal::Error::MigrationConflict)
    ));
    assert_eq!(
        get(&store, "session", "pnA.0").unwrap().as_slice(),
        source.as_slice()
    );
}
#[test]
fn empty_destination_and_missing_device_list_can_migrate_the_input_device() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    alice
        .inject_session(
            "pnA:2@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let empty = codec::encode_session_record(&engine::SessionRecord::default());
    store
        .transaction(|tx| tx.put("session", "lidA_1.2", &empty))
        .unwrap();
    assert_eq!(
        alice
            .migrate_session("pnA:2@s.whatsapp.net", "lidA@lid")
            .unwrap(),
        MigrationReport {
            migrated: 1,
            skipped: 0,
            total: 1
        }
    );
    assert!(
        alice
            .validate_session("pnA:2@s.whatsapp.net")
            .unwrap()
            .exists
    );
}
#[test]
fn malformed_device_lists_or_sessions_fail_instead_of_partially_migrating() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    alice
        .inject_session(
            "pnA@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    assert_eq!(
        alice.migrate_session("", "lidA@lid").unwrap(),
        MigrationReport::default()
    );
    assert_eq!(
        alice.migrate_session("lidX@lid", "lidA@lid").unwrap().total,
        1
    );
    assert_eq!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "invalid")
            .unwrap(),
        MigrationReport::default()
    );
    store
        .transaction(|tx| tx.put("device-list", "pnA", br#"["bad"]"#))
        .unwrap();
    assert!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .is_err()
    );
    assert!(get(&store, "session", "pnA.0").is_some());
    store
        .transaction(|tx| {
            tx.put("device-list", "pnA", br#"["0","2"]"#)?;
            tx.put("session", "pnA.2", &[255])
        })
        .unwrap();
    assert!(
        alice
            .migrate_session("pnA@s.whatsapp.net", "lidA@lid")
            .is_err()
    );
    assert!(get(&store, "session", "pnA.0").is_some());
    assert!(get(&store, "session", "lidA_1.0").is_none());
    assert!(get(&store, "lid-mapping", "pnA").is_none());
}

#[test]
fn rows_from_another_local_account_are_rejected_before_crypto_or_migration() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let other = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    let (foreign_store, foreign) = repo(dir.path().join("foreign.sqlite"), &other);
    foreign
        .inject_session(
            "pnA@s.whatsapp.net",
            &PreKeyBundle::from_credentials(&b, None).unwrap(),
        )
        .unwrap();
    let bytes = get(&foreign_store, "session", "pnA.0").unwrap();
    store
        .transaction(|tx| tx.put("session", "pnA.0", &bytes))
        .unwrap();
    assert!(matches!(
        alice.encrypt("pnA@s.whatsapp.net", b"not another identity"),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    assert!(matches!(
        alice.validate_session("pnA@s.whatsapp.net"),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    assert!(matches!(
        alice.migrate_session("pnA@s.whatsapp.net", "lidA@lid"),
        Err(signal::Error::LocalIdentityMismatch)
    ));
    assert!(get(&store, "lid-mapping", "pnA").is_none());
}
#[test]
fn encoded_lid_and_hosted_domains_are_not_misrouted_as_plain_pns() {
    let dir = tempfile::tempdir().unwrap();
    let a = Credentials::generate().unwrap();
    let b = Credentials::generate().unwrap();
    let (store, alice) = repo(dir.path().join("a.sqlite"), &a);
    LidMappingStore::new(store.clone())
        .store_mappings(&[rustleys_whatsapp::lid_mapping::Mapping {
            pn: "pnA@s.whatsapp.net".into(),
            lid: "lidA@lid".into(),
        }])
        .unwrap();
    let bundle = PreKeyBundle::from_credentials(&b, None).unwrap();
    alice
        .inject_session("pnA_1:2@s.whatsapp.net", &bundle)
        .unwrap();
    assert!(get(&store, "session", "pnA_1.2").is_some());
    assert!(get(&store, "session", "lidA_1.2").is_none());
    alice
        .inject_session("pnA_128:2@s.whatsapp.net", &bundle)
        .unwrap();
    assert!(get(&store, "session", "lidA_129.2").is_some());
}
