use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::Value;
#[test]
fn schema_is_pinned_and_all_message_types_exist() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proto-upstream.json")).unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        rustleys_whatsapp::UPSTREAM_COMMIT
    );
    let digest = rustleys_whatsapp::crypto::sha256(include_bytes!("../proto/WAProto.proto"));
    let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hash, fixture["schema_sha256"].as_str().unwrap());
    let pool = DescriptorPool::decode(rustleys_whatsapp::PROTO_DESCRIPTOR).unwrap();
    for name in fixture["message_types"].as_array().unwrap() {
        assert!(
            pool.get_message_by_name(name.as_str().unwrap()).is_some(),
            "missing {name}"
        );
    }
}
#[test]
fn all_per_field_upstream_wire_vectors_decode_correctly() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proto-upstream.json")).unwrap();
    let pool = DescriptorPool::decode(rustleys_whatsapp::PROTO_DESCRIPTOR).unwrap();
    for (i, row) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let descriptor = pool
            .get_message_by_name(row["type"].as_str().unwrap())
            .unwrap();
        let input = row["schema_input"].to_string();
        let mut json = serde_json::Deserializer::from_str(&input);
        let expected = DynamicMessage::deserialize(descriptor.clone(), &mut json)
            .unwrap_or_else(|e| panic!("JSON vector {i} {} {}: {e}", row["type"], row["field"]));
        let wire: Vec<u8> = row["wire"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        let decoded = DynamicMessage::decode(descriptor.clone(), wire.as_slice())
            .unwrap_or_else(|e| panic!("wire vector {i}: {e}"));
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "vector {i} {} {}",
            row["type"],
            row["field"]
        );
        assert_eq!(
            serde_json::to_value(
                DynamicMessage::decode(descriptor, expected.encode_to_vec().as_slice()).unwrap()
            )
            .unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "Rust re-encode {i}"
        );
    }
}
#[test]
fn generated_typed_handshake_and_large_timestamp_values_preserve_presence() {
    use rustleys_whatsapp::proto::{
        HandshakeMessage, MessageKey, WebMessageInfo, handshake_message,
    };
    let handshake = HandshakeMessage {
        client_hello: Some(handshake_message::ClientHello {
            ephemeral: Some(vec![1; 32]),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        HandshakeMessage::decode(handshake.encode_to_vec().as_slice()).unwrap(),
        handshake
    );
    let message = WebMessageInfo {
        key: Some(MessageKey {
            from_me: Some(false),
            id: Some("synthetic".into()),
            ..Default::default()
        }),
        message_timestamp: Some(u64::MAX),
        ..Default::default()
    };
    assert_eq!(
        WebMessageInfo::decode(message.encode_to_vec().as_slice()).unwrap(),
        message
    );
    assert!(HandshakeMessage::decode([0xff].as_slice()).is_err());
}

#[test]
fn legacy_conflicting_oneof_json_is_explicitly_not_accepted_as_valid_proto_json() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proto-upstream.json")).unwrap();
    let pool = DescriptorPool::decode(rustleys_whatsapp::PROTO_DESCRIPTOR).unwrap();
    for row in fixture["legacy_invalid_oneofs"].as_array().unwrap() {
        let descriptor = pool
            .get_message_by_name(row["type"].as_str().unwrap())
            .unwrap();
        let input = row["input"].to_string();
        let mut json = serde_json::Deserializer::from_str(&input);
        assert!(
            DynamicMessage::deserialize(descriptor.clone(), &mut json).is_err(),
            "expected conflicting-oneof JSON"
        );
        // On the binary wire protobuf's last-one-wins rule applies instead.
        let wire: Vec<u8> = row["wire"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        assert!(DynamicMessage::decode(descriptor, wire.as_slice()).is_ok());
    }
}

#[test]
fn all_schema_field_numbers_types_and_enum_numbers_are_preserved() {
    use prost_reflect::Kind;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/proto-upstream.json")).unwrap();
    let pool = DescriptorPool::decode(rustleys_whatsapp::PROTO_DESCRIPTOR).unwrap();
    for message in fixture["message_fields"].as_array().unwrap() {
        let descriptor = pool
            .get_message_by_name(message["name"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            descriptor.fields().len(),
            message["fields"].as_array().unwrap().len()
        );
        for field in message["fields"].as_array().unwrap() {
            let desc = descriptor
                .get_field_by_name(field["name"].as_str().unwrap())
                .or_else(|| descriptor.get_field_by_json_name(field["name"].as_str().unwrap()))
                .unwrap();
            assert_eq!(u64::from(desc.number()), field["number"].as_u64().unwrap());
            assert_eq!(desc.is_map(), field["map"].as_bool().unwrap());
            assert_eq!(desc.is_list(), field["list"].as_bool().unwrap());
            let actual_kind = if desc.is_map() {
                let Kind::Message(entry) = desc.kind() else {
                    panic!("map must be an entry message")
                };
                let key_kind = match entry.get_field(1).unwrap().kind() {
                    Kind::Uint32 => "uint32",
                    Kind::String => "string",
                    _ => panic!("unexpected schema map key"),
                };
                assert_eq!(key_kind, field["key_type"].as_str().unwrap());
                entry.get_field(2).unwrap().kind()
            } else {
                desc.kind()
            };
            let kind = match actual_kind {
                Kind::Double => "double".into(),
                Kind::Float => "float".into(),
                Kind::Int32 => "int32".into(),
                Kind::Int64 => "int64".into(),
                Kind::Uint32 => "uint32".into(),
                Kind::Uint64 => "uint64".into(),
                Kind::Sint32 => "sint32".into(),
                Kind::Sint64 => "sint64".into(),
                Kind::Fixed32 => "fixed32".into(),
                Kind::Fixed64 => "fixed64".into(),
                Kind::Sfixed32 => "sfixed32".into(),
                Kind::Sfixed64 => "sfixed64".into(),
                Kind::Bool => "bool".into(),
                Kind::String => "string".into(),
                Kind::Bytes => "bytes".into(),
                Kind::Enum(e) => e.full_name().to_owned(),
                Kind::Message(m) => m.full_name().to_owned(),
            };
            assert_eq!(
                kind,
                field["type"].as_str().unwrap(),
                "field {}.{}",
                message["name"],
                field["name"]
            );
        }
    }
    for entry in fixture["enum_types"].as_array().unwrap() {
        let descriptor = pool
            .get_enum_by_name(entry["name"].as_str().unwrap())
            .unwrap();
        for (name, number) in entry["values"].as_object().unwrap() {
            assert_eq!(
                i64::from(descriptor.get_value_by_name(name).unwrap().number()),
                number.as_i64().unwrap()
            );
        }
    }
}
