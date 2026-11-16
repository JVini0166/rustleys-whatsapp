use rustleys_whatsapp::{
    auth::{Bytes, Credentials, registration_id_from_random},
    auth_store::{Category, Error, KeySet, MultiFileStore},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/auth-upstream.json")).unwrap()
}
fn original_creds() -> Credentials {
    Credentials::from_json(
        fixture()["credentials"][0]["serialized"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )
    .unwrap()
}
#[test]
fn original_credentials_preserve_values_extensions_and_auth_state() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(f["synthetic_data"], true);
    for row in f["credentials"].as_array().unwrap() {
        let input = row["serialized"].as_str().unwrap();
        let creds = Credentials::from_json(input.as_bytes()).unwrap();
        let output: Value = serde_json::from_slice(&creds.to_json().unwrap()).unwrap();
        assert_eq!(output, serde_json::from_str::<Value>(input).unwrap());
        assert_eq!(creds.assert_me_id().ok(), row["me"].as_str());
        assert_eq!(format!("{creds:?}"), "Credentials([redacted])");
    }
}
#[test]
fn original_registration_and_buffer_json_representations_match() {
    let f = fixture();
    for row in f["registration"].as_array().unwrap() {
        let b = &row["bytes"];
        assert_eq!(
            registration_id_from_random([
                b[0].as_u64().unwrap() as u8,
                b[1].as_u64().unwrap() as u8
            ]),
            row["result"].as_u64().unwrap() as u16
        );
    }
    for row in f["bytes"].as_array().unwrap() {
        let bytes: Bytes = serde_json::from_str(row["serialized"].as_str().unwrap()).unwrap();
        assert_eq!(json!(bytes.expose()), row["data"]);
        let again: Bytes = serde_json::from_slice(&serde_json::to_vec(&bytes).unwrap()).unwrap();
        assert_eq!(bytes, again);
    }
    for invalid in [
        json!({"type":"Buffer","data":"%%%%"}),
        json!([256]),
        json!([-1]),
        json!({"1":9}),
        json!({"0":"x"}),
        json!({"type":"Buffer"}),
    ] {
        assert!(serde_json::from_value::<Bytes>(invalid).is_err());
    }
}
#[test]
fn invalid_credentials_fail_without_dumping_secret_fields() {
    let original: Value =
        serde_json::from_str(fixture()["credentials"][0]["serialized"].as_str().unwrap()).unwrap();
    let mut bad = original.clone();
    bad["signedPreKey"]["signature"] = json!({"type":"Buffer","data":"AA=="});
    assert!(Credentials::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = original.clone();
    bad["registrationId"] = json!(16384);
    assert!(Credentials::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = original.clone();
    bad["advSecretKey"] = json!("short");
    assert!(Credentials::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = original.clone();
    bad["noiseKey"]["public"] = bad["signedIdentityKey"]["public"].clone();
    assert!(Credentials::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = original;
    bad["nextPreKeyId"] = json!("DO_NOT_PRINT_THIS");
    let error = Credentials::from_json(&serde_json::to_vec(&bad).unwrap()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("DO_NOT_PRINT_THIS"));
}
#[test]
fn generated_credentials_have_valid_signed_keys_and_independent_secrets() {
    let first = Credentials::generate().unwrap();
    let second = Credentials::generate().unwrap();
    first.validate().unwrap();
    second.validate().unwrap();
    assert_ne!(first.noise_key.public, second.noise_key.public);
    assert_ne!(first.adv_secret_key, second.adv_secret_key);
    assert_eq!(first.signed_pre_key.key_id, 1);
    assert_eq!(first.next_pre_key_id, 1);
    assert_eq!(first.first_unuploaded_pre_key_id, 1);
    assert!(!first.registered);
    assert!(!first.account_settings.unarchive_chats);
    assert!(first.assert_me_id().is_err());
    let encoded = first.to_json().unwrap();
    assert_eq!(
        Credentials::from_json(&encoded)
            .unwrap()
            .to_json()
            .unwrap()
            .as_slice(),
        encoded.as_slice()
    );
}
#[test]
fn credentials_reopen_and_corruption_is_not_silently_reinitialized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth");
    let store = MultiFileStore::open(&path).unwrap();
    assert!(store.load_credentials().unwrap().is_none());
    let creds = original_creds();
    store.save_credentials(&creds).unwrap();
    drop(store);
    let store = MultiFileStore::open(&path).unwrap();
    assert_eq!(
        store
            .load_credentials()
            .unwrap()
            .unwrap()
            .to_json()
            .unwrap()
            .as_slice(),
        creds.to_json().unwrap().as_slice()
    );
    std::fs::write(path.join("creds.json"), b"{truncated").unwrap();
    assert!(store.load_or_initialize().is_err());
    assert_eq!(
        std::fs::read(path.join("creds.json")).unwrap(),
        b"{truncated"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(path.join("creds.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
fn batch(category: Category, id: &str, value: Option<Value>) -> KeySet {
    BTreeMap::from([(category, BTreeMap::from([(id.into(), value)]))])
}
#[test]
fn all_key_categories_persist_get_delete_and_import_legacy_names() {
    let dir = tempfile::tempdir().unwrap();
    let store = MultiFileStore::open(dir.path()).unwrap();
    for category in [
        Category::PreKey,
        Category::Session,
        Category::SenderKey,
        Category::SenderKeyMemory,
        Category::AppStateSyncKey,
        Category::AppStateSyncVersion,
        Category::LidMapping,
        Category::DeviceList,
        Category::TcToken,
        Category::IdentityKey,
    ] {
        let value = json!({"type":"Buffer","data":"AAEC/w=="});
        store
            .set(&batch(category, "synthetic/1:2", Some(value.clone())))
            .unwrap();
        let filename = format!("{}-synthetic__1-2.json", category.as_str());
        assert!(dir.path().join(&filename).is_file());
        assert_eq!(
            store
                .get(category, &["synthetic/1:2".into(), "missing".into()])
                .unwrap(),
            BTreeMap::from([
                ("synthetic/1:2".into(), Some(value)),
                ("missing".into(), None)
            ])
        );
        store.set(&batch(category, "synthetic/1:2", None)).unwrap();
        assert!(!dir.path().join(filename).exists());
        store.set(&batch(category, "synthetic/1:2", None)).unwrap();
    }
    std::fs::write(
        dir.path().join("lid-mapping-old.json"),
        br#""synthetic@lid""#,
    )
    .unwrap();
    assert_eq!(
        store.get(Category::LidMapping, &["old".into()]).unwrap()["old"],
        Some(json!("synthetic@lid"))
    );
}
#[test]
fn storage_limits_and_invalid_paths_do_not_partially_write_prevalidated_batch() {
    let dir = tempfile::tempdir().unwrap();
    let store = MultiFileStore::with_limit(dir.path(), 16).unwrap();
    let data = BTreeMap::from([(
        Category::Session,
        BTreeMap::from([
            ("a".into(), Some(json!(1))),
            ("z".into(), Some(json!("x".repeat(50)))),
        ]),
    )]);
    assert!(matches!(store.set(&data), Err(Error::FileTooLarge)));
    assert!(!dir.path().join("session-a.json").exists());
    assert!(matches!(
        store.set(&batch(Category::Session, "..\\escape", Some(json!(1)))),
        Err(Error::InvalidPath)
    ));
    std::fs::write(dir.path().join("session-large.json"), [0; 17]).unwrap();
    assert!(matches!(
        store.get(Category::Session, &["large".into()]),
        Err(Error::FileTooLarge)
    ));
    std::fs::write(dir.path().join("session-broken.json"), b"{").unwrap();
    assert!(matches!(
        store.get(Category::Session, &["broken".into()]),
        Err(Error::InvalidJson)
    ));
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"x").unwrap();
    assert!(MultiFileStore::open(file).is_err());
}
#[test]
fn concurrent_instances_never_observe_torn_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MultiFileStore::open(dir.path()).unwrap());
    let mut threads = Vec::new();
    for writer in 0..4 {
        let store = Arc::new(MultiFileStore::open(dir.path()).unwrap());
        threads.push(std::thread::spawn(move || {
            for n in 0..8 {
                let text = format!("{writer}:{n}:") + &"x".repeat(4096);
                store
                    .set(&batch(Category::Session, "concurrent", Some(json!(text))))
                    .unwrap();
                let read = store
                    .get(Category::Session, &["concurrent".into()])
                    .unwrap();
                assert!(
                    read["concurrent"]
                        .as_ref()
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .ends_with(&"x".repeat(4096))
                );
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    assert!(
        store
            .get(Category::Session, &["concurrent".into()])
            .unwrap()["concurrent"]
            .is_some()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2); // data and stable lock; no leaked temp files.
}
#[cfg(unix)]
#[test]
fn symlinks_cannot_redirect_credential_or_key_reads_and_writes() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth");
    let store = MultiFileStore::open(&path).unwrap();
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, path.join("creds.json")).unwrap();
    assert!(store.load_credentials().is_err());
    assert!(store.save_credentials(&original_creds()).is_err());
    symlink(&outside, path.join("session-test.json")).unwrap();
    assert!(store.get(Category::Session, &["test".into()]).is_err());
    assert!(
        store
            .set(&batch(Category::Session, "test", Some(json!(1))))
            .is_err()
    );
    assert_eq!(std::fs::read(outside).unwrap(), b"unchanged");
    let linked = dir.path().join("linked");
    symlink(&path, &linked).unwrap();
    assert!(MultiFileStore::open(linked).is_err());
}

#[test]
fn extension_fields_cannot_shadow_known_credential_fields() {
    let mut creds = original_creds();
    creds.extra.insert("noiseKey".into(), json!("shadow"));
    assert!(creds.to_json().is_err());
    let mut creds = original_creds();
    creds
        .account_settings
        .extra
        .insert("unarchiveChats".into(), json!(true));
    assert!(creds.to_json().is_err());
    let dir = tempfile::tempdir().unwrap();
    assert!(MultiFileStore::with_limit(dir.path(), usize::MAX).is_err());
}

#[test]
fn multi_file_adapter_treats_javascript_falsy_values_as_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let store = MultiFileStore::open(dir.path()).unwrap();
    for value in [Value::Null, json!(false), json!(0), json!("")] {
        store
            .set(&batch(
                Category::LidMapping,
                "synthetic",
                Some(json!("synthetic@lid")),
            ))
            .unwrap();
        store
            .set(&batch(Category::LidMapping, "synthetic", Some(value)))
            .unwrap();
        assert_eq!(
            store
                .get(Category::LidMapping, &["synthetic".into()])
                .unwrap()["synthetic"],
            None
        );
    }
}

#[test]
fn explicit_null_and_arbitrary_additional_data_survive_export() {
    let base: Value =
        serde_json::from_str(fixture()["credentials"][0]["serialized"].as_str().unwrap()).unwrap();
    for additional in [
        Value::Null,
        json!(false),
        json!(0),
        json!(""),
        json!([null,1,{"future":true}]),
    ] {
        let mut value = base.clone();
        value["additionalData"] = additional;
        value["accountSettings"]["defaultDisappearingMode"] = Value::Null;
        let creds = Credentials::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&creds.to_json().unwrap()).unwrap(),
            value
        );
    }
}

#[test]
fn readers_without_rust_lock_only_observe_complete_atomic_replacements() {
    let dir = tempfile::tempdir().unwrap();
    let store = MultiFileStore::open(dir.path()).unwrap();
    let payload = "x".repeat(32768);
    store
        .set(&batch(
            Category::Session,
            "atomic",
            Some(json!({"generation":0,"payload":payload})),
        ))
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer_barrier = barrier.clone();
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for n in 1..=8 {
            store
                .set(&batch(
                    Category::Session,
                    "atomic",
                    Some(json!({"generation":n,"payload":payload})),
                ))
                .unwrap();
        }
    });
    barrier.wait();
    for _ in 0..128 {
        let raw = std::fs::read(dir.path().join("session-atomic.json")).unwrap();
        let value: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["payload"].as_str().unwrap().len(), 32768);
        assert!(value["generation"].as_u64().unwrap() <= 8);
    }
    writer.join().unwrap();
    let final_value: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("session-atomic.json")).unwrap())
            .unwrap();
    assert_eq!(final_value["generation"], 8);
}
