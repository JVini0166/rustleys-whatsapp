use rustleys_whatsapp::binary::*;
use serde_json::{Value, json};
fn node(v: &Value) -> Node {
    let content = match &v["content"] {
        Value::Null => None,
        Value::String(s) => Some(Content::Text(s.clone())),
        Value::Array(a) => Some(Content::Nodes(a.iter().map(node).collect())),
        v => Some(Content::Bytes(
            v["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_u64().unwrap() as u8)
                .collect(),
        )),
    };
    Node {
        tag: v["tag"].as_str().unwrap().into(),
        attrs: v["attrs"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
            .collect(),
        content,
    }
}
fn norm(n: &Node) -> Value {
    let attrs: serde_json::Map<String, Value> =
        n.attrs.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let content = match &n.content {
        None => Value::Null,
        Some(Content::Text(s)) => json!(s),
        Some(Content::Bytes(b)) => json!({"bytes":b}),
        Some(Content::Nodes(a)) => Value::Array(a.iter().map(norm).collect()),
    };
    json!({"tag":n.tag,"attrs":attrs,"content":content})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/binary-upstream.json")).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect()
}
#[test]
fn exact_wire_bytes_and_decoding_match_upstream() {
    let f = fixture();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    for (i, row) in f["cases"].as_array().unwrap().iter().enumerate() {
        let expected = bytes(&row["wire"]);
        assert_eq!(
            encode(&node(&row["input"])).unwrap(),
            expected,
            "encode vector {i}"
        );
        assert_eq!(
            norm(&decode(&expected).unwrap()),
            row["decoded"],
            "decode vector {i}"
        );
    }
    assert_eq!(
        norm(&decode(&bytes(&f["compressed"])).unwrap()),
        f["cases"].as_array().unwrap().last().unwrap()["decoded"]
    );
}
#[test]
fn rejects_truncation_and_respects_bounds() {
    let n = Node {
        tag: "message".into(),
        attrs: vec![("id".into(), "123".into())],
        content: Some(Content::Bytes(vec![1, 2, 3, 4])),
    };
    let wire = encode(&n).unwrap();
    for i in 0..wire.len() {
        assert!(decode(&wire[..i]).is_err(), "truncated {i}");
    }
    assert!(
        encode_with_limits(
            &n,
            Limits {
                max_bytes: 4,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        decode_with_limits(
            &wire,
            Limits {
                max_bytes: 4,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        encode(&Node {
            tag: String::new(),
            attrs: vec![],
            content: None
        })
        .is_err()
    );
    let mut nested = n.clone();
    for _ in 0..10 {
        nested = Node {
            tag: "list".into(),
            attrs: vec![],
            content: Some(Content::Nodes(vec![nested])),
        };
    }
    let limits = Limits {
        max_depth: 5,
        ..Limits::default()
    };
    assert!(encode_with_limits(&nested, limits).is_err());
    assert!(decode_with_limits(&encode(&nested).unwrap(), limits).is_err());
    assert!(
        decode_with_limits(
            &encode(&nested).unwrap(),
            Limits {
                max_nodes: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let compressed = bytes(&fixture()["compressed"]);
    assert!(
        decode_with_limits(
            &compressed,
            Limits {
                max_bytes: 100,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn extended_lengths_and_list16_round_trip() {
    for length in [255, 256, (1 << 20) - 1, 1 << 20] {
        let n = Node {
            tag: "body".into(),
            attrs: vec![],
            content: Some(Content::Bytes(vec![b'x'; length])),
        };
        assert_eq!(decode(&encode(&n).unwrap()).unwrap(), n);
    }
    let n = Node {
        tag: "item".into(),
        attrs: vec![],
        content: None,
    };
    let list = Node {
        tag: "list".into(),
        attrs: vec![],
        content: Some(Content::Nodes(vec![n; 256])),
    };
    assert_eq!(decode(&encode(&list).unwrap()).unwrap(), list);
}
#[test]
fn malformed_frames_do_not_panic() {
    let mut seed = 42u32;
    for length in 0..256 {
        for _ in 0..8 {
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = decode_with_limits(
                &bytes,
                Limits {
                    max_bytes: 4096,
                    max_depth: 12,
                    max_nodes: 64,
                    max_attributes: 128,
                },
            );
        }
    }
}
#[test]
fn special_jid_tags_and_concatenated_cursor() {
    // [list8,2,'iq',FB_JID,raw8,user,device16,raw8,server]
    let fb = [
        0, 248, 2, 252, 2, b'i', b'q', 246, 252, 1, b'a', 0, 5, 252, 3, b'c', b'.', b'u',
    ];
    assert_eq!(
        decode(&fb).unwrap().content,
        Some(Content::Text("a:5@c.u".into()))
    );
    let interop = [0, 248, 2, 252, 2, b'i', b'q', 245, 252, 1, b'a', 0, 5, 0, 9];
    assert_eq!(
        decode(&interop).unwrap().content,
        Some(Content::Text("9-a:5@interop".into()))
    );
    let n = Node {
        tag: "item".into(),
        attrs: vec![],
        content: None,
    };
    let wire = encode(&n).unwrap();
    let mut double = wire[1..].to_vec();
    double.extend_from_slice(&wire[1..]);
    let mut cursor = 0;
    assert_eq!(
        decode_decompressed(&double, &mut cursor, Limits::default()).unwrap(),
        n
    );
    assert_eq!(cursor, wire.len() - 1);
    assert_eq!(
        decode_decompressed(&double, &mut cursor, Limits::default()).unwrap(),
        n
    );
    assert_eq!(cursor, double.len());
}

#[test]
fn incomplete_zlib_streams_are_rejected() {
    let compressed = bytes(&fixture()["compressed"]);
    for i in 1..compressed.len() {
        assert!(
            decode(&compressed[..i]).is_err(),
            "compressed prefix {i}/{}",
            compressed.len()
        );
    }
}

#[test]
fn attribute_budget_is_global_and_counts_duplicates_before_deduplication() {
    let child = Node {
        tag: "item".into(),
        attrs: vec![("id".into(), "one".into()), ("id".into(), "two".into())],
        content: None,
    };
    let tree = Node {
        tag: "list".into(),
        attrs: vec![("id".into(), "root".into())],
        content: Some(Content::Nodes(vec![child.clone(), child])),
    };
    let wire = encode(&tree).unwrap();
    let limits = Limits {
        max_attributes: 4,
        ..Default::default()
    };
    assert_eq!(
        encode_with_limits(&tree, limits),
        Err(rustleys_whatsapp::binary::Error("attribute limit"))
    );
    assert_eq!(
        decode_with_limits(&wire, limits),
        Err(rustleys_whatsapp::binary::Error("attribute limit"))
    );
    assert!(
        decode_with_limits(
            &wire,
            Limits {
                max_attributes: 5,
                ..Default::default()
            }
        )
        .is_ok()
    );
}
#[test]
fn large_attribute_tables_keep_first_key_order_and_last_duplicate_value() {
    let mut attrs: Vec<_> = (0..5000)
        .map(|n| (format!("field-{n}"), format!("value-{n}")))
        .collect();
    attrs.push(("field-2".into(), "updated".into()));
    let source = Node {
        tag: "item".into(),
        attrs,
        content: None,
    };
    let result = decode(&encode(&source).unwrap()).unwrap();
    assert_eq!(result.attrs.len(), 5000);
    assert_eq!(result.attrs[2], ("field-2".into(), "updated".into()));
    for n in [0, 1, 3, 4999] {
        assert_eq!(
            result.attrs[n],
            (format!("field-{n}"), format!("value-{n}"))
        );
    }
}
