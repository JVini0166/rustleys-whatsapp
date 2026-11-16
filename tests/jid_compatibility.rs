use rustleys_whatsapp::jid::*;
use serde_json::Value;

#[test]
fn matches_pinned_upstream_jid_vectors() {
    let data: Value = serde_json::from_str(include_str!("fixtures/jid-upstream.json")).unwrap();
    assert_eq!(data["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    for (i, row) in data["cases"].as_array().unwrap().iter().enumerate() {
        let text = |k| row[k].as_str().unwrap();
        let num = |k| row[k].as_u64().map(|n| u32::try_from(n).unwrap());
        let encoded = jid_encode(text("user"), text("server"), num("device"), num("agent"));
        assert_eq!(encoded, text("encoded"), "encode case {i}");
        let decoded = jid_decode(&encoded).unwrap();
        let expected = &row["decoded"];
        assert_eq!(decoded.user, expected["user"].as_str().unwrap(), "user {i}");
        assert_eq!(
            decoded.server,
            expected["server"].as_str().unwrap(),
            "server {i}"
        );
        assert_eq!(
            decoded.device.map(u64::from),
            expected["device"].as_u64(),
            "device {i}"
        );
        assert_eq!(
            u64::from(decoded.domain_type),
            expected["domainType"].as_u64().unwrap(),
            "domain {i}"
        );
        assert_eq!(
            jid_normalized_user(Some(&encoded)),
            text("normalized"),
            "normalized {i}"
        );
        assert_eq!(
            transfer_device(&encoded, "target@lid").unwrap(),
            text("transferred"),
            "transfer {i}"
        );
        let predicates = [
            is_jid_meta_ai(Some(&encoded)),
            is_pn_user(Some(&encoded)),
            is_lid_user(Some(&encoded)),
            is_jid_broadcast(Some(&encoded)),
            is_jid_group(Some(&encoded)),
            is_jid_status_broadcast(&encoded),
            is_jid_newsletter(Some(&encoded)),
            is_hosted_pn_user(Some(&encoded)),
            is_hosted_lid_user(Some(&encoded)),
            is_jid_bot(Some(&encoded)),
        ];
        for (j, actual) in predicates.iter().enumerate() {
            assert_eq!(
                *actual,
                row["predicates"][j].as_bool().unwrap(),
                "predicate {j}, case {i}"
            );
        }
    }
}

#[test]
fn upstream_identity_semantics_and_invalid_inputs() {
    assert!(are_jids_same_user(Some("alice:2@lid"), Some("alice@c.us")));
    assert!(are_jids_same_user(None, None));
    assert!(are_jids_same_user(Some("no-at"), None));
    assert!(!are_jids_same_user(Some("alice@lid"), Some("bob@lid")));
    assert_eq!(jid_normalized_user(None), "");
    assert_eq!(jid_decode("invalid"), Err(Error::MissingSeparator));
    assert_eq!(jid_decode("alice:NaN@lid"), Err(Error::InvalidDevice));
    assert_eq!(
        jid_decode("alice_x@s.whatsapp.net"),
        Err(Error::InvalidAgent)
    );
    assert_eq!(jid_decode("alice_x@lid").unwrap().domain_type, 1);
    assert_eq!(jid_decode("a:2:3@lid").unwrap().device, Some(2));
    assert_eq!(jid_decode("a_1_9@c.us").unwrap().domain_type, 1);
    assert_eq!(
        transfer_device("missing", "alice@lid").unwrap(),
        "alice@lid"
    );
    assert_eq!(
        transfer_device("alice@lid", "missing"),
        Err(Error::MissingSeparator)
    );
    for (domain, expected) in [
        (0, "custom"),
        (1, "lid"),
        (128, "hosted"),
        (129, "hosted.lid"),
        (42, "custom"),
    ] {
        assert_eq!(
            get_server_from_domain_type("custom", Some(domain)),
            expected
        );
    }
}
