use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use rustleys_whatsapp::{
    auth::{Bytes, Credentials},
    auth_store::MultiFileStore,
    binary::{Content, Node},
    crypto,
    pairing::{self, ClientConfig, Error},
    proto,
};
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/pairing-upstream.json")).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::from_value(value.clone()).unwrap()
}
fn creds(f: &Value) -> Credentials {
    Credentials::from_json(f["credentials"].as_str().unwrap().as_bytes()).unwrap()
}
fn node(value: &Value) -> Node {
    Node {
        tag: value["tag"].as_str().unwrap().into(),
        attrs: value["attrs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect(),
        content: match &value["content"] {
            Value::Null => None,
            Value::Array(nodes) => Some(Content::Nodes(nodes.iter().map(node).collect())),
            Value::Object(map) => Some(Content::Bytes(bytes(&map["bytes"]))),
            Value::String(s) => Some(Content::Text(s.clone())),
            _ => panic!("fixture content"),
        },
    }
}
fn account_bytes(creds: &Credentials, key: &str) -> Vec<u8> {
    let value = &creds.account.as_ref().unwrap()[key];
    if let Some(text) = value.as_str() {
        STANDARD.decode(text).unwrap()
    } else {
        serde_json::from_value::<Bytes>(value.clone())
            .unwrap()
            .expose()
            .to_vec()
    }
}

#[test]
fn registration_login_and_qr_match_original_functions() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    assert_eq!(f["synthetic_data"], true);
    let creds = creds(&f);
    for row in f["payloads"].as_array().unwrap() {
        let config: ClientConfig = serde_json::from_value(row["config"].clone()).unwrap();
        assert_eq!(
            pairing::registration_payload(&creds, &config)
                .unwrap()
                .encode_to_vec(),
            bytes(&row["registration"])
        );
        for login in row["logins"].as_array().unwrap() {
            assert_eq!(
                pairing::login_payload(login["jid"].as_str().unwrap(), &config)
                    .unwrap()
                    .encode_to_vec(),
                bytes(&login["bytes"])
            );
        }
        let qr = pairing::pairing_qr_data("synthetic-ref", &creds, &config.browser).unwrap();
        assert_eq!(qr.expose(), row["qr"].as_str().unwrap());
        assert!(!format!("{qr:?}").contains(&creds.adv_secret_key));
        assert_eq!(
            pairing::companion_web_client_type(&config.browser).to_string(),
            row["companion"]
        );
    }
}
#[test]
fn verified_pairing_is_persisted_before_ack_and_reply_signature_is_valid() {
    let f = fixture();
    for row in f["pairings"].as_array().unwrap() {
        let mut creds = creds(&f);
        let dir = tempfile::tempdir().unwrap();
        let store = MultiFileStore::open(dir.path()).unwrap();
        store.save_credentials(&creds).unwrap();
        let update = pairing::configure_successful_pairing(&node(&row["stanza"]), &creds).unwrap();
        assert!(!format!("{update:?}").contains(&creds.adv_secret_key));
        assert_eq!(update.credentials().me.as_ref().unwrap(), &row["me"]);
        let reply = update.persist_and_reply(&store, &mut creds).unwrap();
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
        assert_eq!(
            creds.signal_identities.as_ref().unwrap(),
            &row["identities"]
        );
        assert_eq!(creds.platform.as_deref(), row["platform"].as_str());
        for key in ["details", "accountSignatureKey", "accountSignature"] {
            let expected = STANDARD
                .decode(row["account"][key].as_str().unwrap())
                .unwrap();
            assert_eq!(account_bytes(&creds, key), expected);
            assert_eq!(creds.account.as_ref().unwrap()[key], row["account"][key]);
        }
        let mut message = vec![6, 1];
        message.extend(account_bytes(&creds, "details"));
        message.extend(creds.signed_identity_key.public.expose());
        message.extend(account_bytes(&creds, "accountSignatureKey"));
        assert!(crypto::verify_signature(
            creds.signed_identity_key.public.expose(),
            &message,
            &account_bytes(&creds, "deviceSignature")
        ));
        let Some(Content::Nodes(top)) = reply.content else {
            panic!()
        };
        let Some(Content::Nodes(children)) = &top[0].content else {
            panic!()
        };
        let Some(Content::Bytes(encoded)) = &children[0].content else {
            panic!()
        };
        let signed = proto::AdvSignedDeviceIdentity::decode(encoded.as_slice()).unwrap();
        assert!(signed.account_signature_key.is_none());
        assert_eq!(
            signed.device_signature.as_deref().unwrap(),
            account_bytes(&creds, "deviceSignature")
        );
    }
}
#[test]
fn bad_hmac_and_original_bad_signature_acceptance_are_rejected_without_changes() {
    let f = fixture();
    let creds = creds(&f);
    let before = creds.to_json().unwrap();
    for row in f["negative"].as_array().unwrap() {
        let error =
            pairing::configure_successful_pairing(&node(&row["stanza"]), &creds).unwrap_err();
        assert_eq!(format!("{error:?}"), row["expected"].as_str().unwrap());
        assert_eq!(before.as_slice(), creds.to_json().unwrap().as_slice());
        if row["name"] == "bad_account_signature" {
            assert_eq!(row["originalAccepted"], true);
        }
    }
}
#[test]
fn persistence_failure_and_stale_in_memory_or_on_disk_state_do_not_release_ack() {
    let f = fixture();
    let stanza = node(&f["pairings"][0]["stanza"]);
    let mut creds = creds(&f);
    let before = creds.to_json().unwrap();
    let update = pairing::configure_successful_pairing(&stanza, &creds).unwrap();
    assert!(matches!(
        update.commit_and_reply(&mut creds, |_, _| Err(Error::Storage)),
        Err(Error::Storage)
    ));
    assert_eq!(creds.to_json().unwrap().as_slice(), before.as_slice());
    let update = pairing::configure_successful_pairing(&stanza, &creds).unwrap();
    creds.extra.insert("concurrentUpdate".into(), json!(true));
    assert!(matches!(
        update.commit_and_reply(&mut creds, |_, _| panic!("must not persist stale snapshot")),
        Err(Error::StaleUpdate)
    ));
    let dir = tempfile::tempdir().unwrap();
    let store = MultiFileStore::open(dir.path()).unwrap();
    store.save_credentials(&creds).unwrap();
    let update = pairing::configure_successful_pairing(&stanza, &creds).unwrap();
    let mut other = creds.clone();
    other.extra.insert("externalWriter".into(), json!(42));
    MultiFileStore::open(dir.path())
        .unwrap()
        .save_credentials(&other)
        .unwrap();
    assert!(matches!(
        update.persist_and_reply(&store, &mut creds),
        Err(Error::StaleUpdate)
    ));
    assert_eq!(
        store
            .load_credentials()
            .unwrap()
            .unwrap()
            .to_json()
            .unwrap()
            .as_slice(),
        other.to_json().unwrap().as_slice()
    );
    assert!(!creds.extra.contains_key("externalWriter"));
    let empty = tempfile::tempdir().unwrap();
    let store = MultiFileStore::open(empty.path()).unwrap();
    let update = pairing::configure_successful_pairing(&stanza, &creds).unwrap();
    assert!(matches!(
        update.persist_and_reply(&store, &mut creds),
        Err(Error::StaleUpdate)
    ));
    assert!(store.load_credentials().unwrap().is_none());
}
#[test]
fn repeated_pair_success_deduplicates_identity_and_preserves_other_fields() {
    let f = fixture();
    let stanza = node(&f["pairings"][0]["stanza"]);
    let mut creds = creds(&f);
    creds.extra.insert("extension".into(), json!({"opaque":1}));
    pairing::configure_successful_pairing(&stanza, &creds)
        .unwrap()
        .commit_and_reply(&mut creds, |_, _| Ok(()))
        .unwrap();
    let identities = creds.signal_identities.clone();
    pairing::configure_successful_pairing(&stanza, &creds)
        .unwrap()
        .commit_and_reply(&mut creds, |_, _| Ok(()))
        .unwrap();
    assert_eq!(identities, creds.signal_identities);
    assert_eq!(creds.extra["extension"], json!({"opaque":1}));
    // Legacy Buffer arrays and modern BufferJSON base64 are the same identity.
    let correct: Bytes = serde_json::from_value(
        creds.signal_identities.as_ref().unwrap()[0]["identifierKey"].clone(),
    )
    .unwrap();
    creds.signal_identities.as_mut().unwrap()[0]["identifierKey"] =
        json!({"type":"Buffer","data":correct.expose()});
    assert!(pairing::configure_successful_pairing(&stanza, &creds).is_ok());
    let array = creds
        .signal_identities
        .as_mut()
        .unwrap()
        .as_array_mut()
        .unwrap();
    array[0]["identifierKey"] = json!({"type":"Buffer","data":vec![5;33]});
    assert_eq!(
        pairing::configure_successful_pairing(&stanza, &creds).unwrap_err(),
        Error::IdentityConflict
    );
}
#[test]
fn invalid_input_and_unsafe_javascript_number_coercions_fail_explicitly() {
    let f = fixture();
    let mut creds = creds(&f);
    let config = ClientConfig::default();
    assert!(
        pairing::client_payload(&creds, &config)
            .unwrap()
            .device_pairing_data
            .is_some()
    );
    creds.me = Some(json!({"id":"15550001111:5@s.whatsapp.net"}));
    assert_eq!(
        pairing::client_payload(&creds, &config).unwrap().device,
        Some(5)
    );
    for jid in [
        "not-jid",
        "abc@s.whatsapp.net",
        "18446744073709551615@lid",
        "9007199254740992@lid",
        "123@g.us",
    ] {
        assert_eq!(
            pairing::login_payload(jid, &config).unwrap_err(),
            Error::InvalidJid
        );
    }
    for reference in ["", "one,two", "unsafe\nref"] {
        assert!(pairing::pairing_qr_data(reference, &creds, &config.browser).is_err());
    }
    let mut stanza = node(&f["pairings"][0]["stanza"]);
    stanza.attrs.push(("id".into(), "duplicate".into()));
    assert_eq!(
        pairing::configure_successful_pairing(&stanza, &creds).unwrap_err(),
        Error::InvalidStanza
    );
    let missing = Node {
        tag: "iq".into(),
        attrs: vec![("id".into(), "test".into())],
        content: None,
    };
    assert_eq!(
        pairing::configure_successful_pairing(&missing, &creds).unwrap_err(),
        Error::MissingIdentity
    );
    let mut invalid = config.clone();
    invalid.browser[1].clear();
    assert_eq!(
        pairing::registration_payload(&creds, &invalid).unwrap_err(),
        Error::InvalidConfig
    );
}

fn qr_stanza() -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![
            ("id".into(), "qr-challenge".into()),
            ("type".into(), "set".into()),
        ],
        content: Some(Content::Nodes(vec![Node {
            tag: "pair-device".into(),
            attrs: vec![],
            content: Some(Content::Nodes(
                ["ref-1", "ref-2"]
                    .iter()
                    .map(|r| Node {
                        tag: "ref".into(),
                        attrs: vec![],
                        content: Some(Content::Bytes(r.as_bytes().to_vec())),
                    })
                    .collect(),
            )),
        }])),
    }
}
#[test]
fn qr_rotation_obeys_first_and_subsequent_deadlines_without_skipping_refs() {
    use pairing::QrPoll;
    use std::time::{Duration, Instant};
    let f = fixture();
    let creds = creds(&f);
    let config = ClientConfig::default();
    let (ack, mut rotation) =
        pairing::QrRotation::from_stanza(&qr_stanza(), &creds, &config.browser, None).unwrap();
    assert!(ack.attrs.contains(&("id".into(), "qr-challenge".into())));
    assert!(ack.attrs.contains(&("type".into(), "result".into())));
    let now = Instant::now();
    let QrPoll::Ready { qr, expires_at } = rotation.poll(now).unwrap() else {
        panic!()
    };
    assert_eq!(
        qr.expose(),
        pairing::pairing_qr_data("ref-1", &creds, &config.browser)
            .unwrap()
            .expose()
    );
    assert_eq!(expires_at, now + Duration::from_secs(60));
    assert!(
        matches!(rotation.poll(now+Duration::from_secs(59)).unwrap(),QrPoll::Waiting{deadline}if deadline==expires_at)
    );
    let QrPoll::Ready { qr, expires_at } = rotation.poll(expires_at).unwrap() else {
        panic!()
    };
    assert_eq!(
        qr.expose(),
        pairing::pairing_qr_data("ref-2", &creds, &config.browser)
            .unwrap()
            .expose()
    );
    assert_eq!(expires_at, now + Duration::from_secs(80));
    assert!(matches!(
        rotation.poll(expires_at).unwrap(),
        QrPoll::Exhausted
    ));
}
#[test]
fn custom_qr_timeout_cancellation_and_invalid_references_are_explicit() {
    use pairing::QrPoll;
    use std::time::{Duration, Instant};
    let f = fixture();
    let creds = creds(&f);
    let browser = ClientConfig::default().browser;
    let (_, mut rotation) = pairing::QrRotation::from_stanza(
        &qr_stanza(),
        &creds,
        &browser,
        Some(Duration::from_secs(7)),
    )
    .unwrap();
    let now = Instant::now();
    assert!(
        matches!(rotation.poll(now).unwrap(),QrPoll::Ready{expires_at,..}if expires_at==now+Duration::from_secs(7))
    );
    assert!(
        matches!(rotation.poll(now+Duration::from_secs(7)).unwrap(),QrPoll::Ready{expires_at,..}if expires_at==now+Duration::from_secs(14))
    );
    rotation.cancel();
    assert!(matches!(
        rotation.poll(now + Duration::from_secs(20)).unwrap(),
        QrPoll::Exhausted
    ));
    assert!(
        pairing::QrRotation::from_stanza(&qr_stanza(), &creds, &browser, Some(Duration::ZERO))
            .is_err()
    );
    let mut malformed = qr_stanza();
    let Some(Content::Nodes(children)) = &mut malformed.content else {
        panic!()
    };
    children[0].content = Some(Content::Nodes(vec![Node {
        tag: "ref".into(),
        attrs: vec![],
        content: Some(Content::Bytes(vec![255])),
    }]));
    assert!(pairing::QrRotation::from_stanza(&malformed, &creds, &browser, None).is_err());
}

#[test]
fn concurrent_pairing_updates_have_exactly_one_durable_winner() {
    use std::sync::{Arc, Barrier};
    let f = fixture();
    let original = creds(&f);
    let stanza = node(&f["pairings"][0]["stanza"]);
    let directory = tempfile::tempdir().unwrap();
    MultiFileStore::open(directory.path())
        .unwrap()
        .save_credentials(&original)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let path = directory.path().to_path_buf();
        let mut current = original.clone();
        let update = pairing::configure_successful_pairing(&stanza, &current).unwrap();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let store = MultiFileStore::open(path).unwrap();
            barrier.wait();
            let result = update.persist_and_reply(&store, &mut current);
            (result, current.to_json().unwrap())
        }));
    }
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|(r, _)| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|(r, _)| matches!(r, Err(Error::StaleUpdate)))
            .count(),
        1
    );
    let saved = MultiFileStore::open(directory.path())
        .unwrap()
        .load_credentials()
        .unwrap()
        .unwrap()
        .to_json()
        .unwrap();
    assert_eq!(
        saved.as_slice(),
        outcomes
            .iter()
            .find(|(r, _)| r.is_ok())
            .unwrap()
            .1
            .as_slice()
    );
    assert_eq!(
        outcomes
            .iter()
            .find(|(r, _)| r.is_err())
            .unwrap()
            .1
            .as_slice(),
        original.to_json().unwrap().as_slice()
    );
}
