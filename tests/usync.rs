use rustleys_whatsapp::{
    binary::{Content, Node},
    usync::{self, Builtin, Protocol, Query, User},
};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
fn node(value: &Value) -> Result<Node, Box<dyn std::error::Error>> {
    let attrs = value["attrs"]
        .as_object()
        .ok_or("attrs required")?
        .iter()
        .map(|(key, v)| Ok((key.clone(), v.as_str().ok_or("attribute string")?.into())))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(Node {
        tag: value["tag"].as_str().ok_or("tag required")?.into(),
        attrs,
        content: match &value["content"] {
            Value::Null => None,
            Value::String(text) => Some(Content::Text(text.clone())),
            Value::Array(nodes) => Some(Content::Nodes(
                nodes.iter().map(node).collect::<Result<_, _>>()?,
            )),
            Value::Object(map) => Some(Content::Bytes(serde_json::from_value(
                map.get("bytes").ok_or("bytes required")?.clone(),
            )?)),
            _ => return Err("invalid content".into()),
        },
    })
}

fn config(v: &Value) -> Query {
    let mut q = Query::default();
    for p in v["protocols"].as_array().unwrap() {
        q = q.with_protocol(serde_json::from_value::<Builtin>(p.clone()).unwrap());
    }
    q.users = serde_json::from_value::<Vec<User>>(v["users"].clone()).unwrap();
    if let Some(mode) = v["mode"].as_str() {
        q.mode = mode.into();
    }
    if let Some(context) = v["context"].as_str() {
        q.context = context.into();
    }
    q
}
fn fixture() -> Value {
    let v: Value = serde_json::from_str(include_str!("fixtures/usync-upstream.json")).unwrap();
    assert_eq!(v["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    v
}
#[test]
fn original_socket_builders_match_exact_wire_for_all_protocols_and_user_precedence() {
    for row in fixture()["builds"].as_array().unwrap() {
        let result = config(&row["config"]).build(row["sid"].as_str().unwrap());
        if row["error"] == true {
            assert!(result.is_err());
        } else {
            assert_eq!(
                rustleys_whatsapp::binary::encode(&result.unwrap()).unwrap(),
                serde_json::from_value::<Vec<u8>>(row["wire"].clone()).unwrap(),
                "{row}"
            );
        }
    }
}
#[test]
fn all_original_protocol_parsers_match_dates_numbers_bytes_and_error_cases() {
    for row in fixture()["parsers"].as_array().unwrap() {
        let p: Builtin = serde_json::from_value(row["protocol"].clone()).unwrap();
        let result = p.parse(&node(&row["node"]).unwrap());
        if row["error"] == true {
            assert!(result.is_err(), "{row}");
        } else {
            assert_eq!(
                result.unwrap().unwrap_or(Value::Null),
                row["expected"],
                "{row}"
            );
        }
    }
}
#[test]
fn aggregate_results_preserve_duplicates_omissions_ids_and_original_bot_failure() {
    for row in fixture()["results"].as_array().unwrap() {
        let result = config(&row["config"]).parse(Some(&node(&row["node"]).unwrap()));
        if row["error"] == true {
            assert!(result.is_err());
        } else {
            assert_eq!(
                serde_json::to_value(result.unwrap()).unwrap(),
                row["expected"],
                "{row}"
            );
        }
    }
    assert!(Query::default().parse(None).unwrap().is_none());
}
#[test]
fn bounded_builds_and_responses_reject_excess_before_parsing() {
    let mut q = Query::default()
        .with_protocol(Builtin::Contact)
        .with_user(User::default().with_id("1@s.whatsapp.net"));
    assert!(matches!(q.build(""), Err(usync::Error::InvalidSid)));
    q.limits.max_users = 0;
    assert!(matches!(q.build("test"), Err(usync::Error::Limit)));
    q.limits = Default::default();
    let response = node(&fixture()["results"][0]["node"]).unwrap();
    for field in 0..5 {
        q.limits = Default::default();
        match field {
            0 => q.limits.max_nodes = 1,
            1 => q.limits.max_bytes = 1,
            2 => q.limits.max_depth = 0,
            3 => q.limits.max_users = 0,
            _ => q.limits.max_attributes = 0,
        };
        assert!(matches!(q.parse(Some(&response)), Err(usync::Error::Limit)));
    }
    q.limits = Default::default();
    q.limits.max_protocols = 0;
    assert!(matches!(q.parse(Some(&response)), Err(usync::Error::Limit)));
}
struct Custom(&'static str, Value);
impl Protocol for Custom {
    fn name(&self) -> &str {
        self.0
    }
    fn query_element(&self) -> Node {
        Node {
            tag: self.0.into(),
            attrs: vec![],
            content: None,
        }
    }
    fn user_element(&self, _: &User) -> Option<Node> {
        None
    }
    fn parse(&self, _: &Node) -> usync::Result<Option<Value>> {
        Ok(Some(self.1.clone()))
    }
}
#[test]
fn custom_protocols_last_registered_parser_wins_and_id_cannot_be_shadowed() {
    let q = Query::default()
        .with_protocol(Custom("custom", json!(1)))
        .with_protocol(Custom("custom", json!(2)))
        .with_protocol(Custom("id", json!("override")));
    let response=node(&json!({"tag":"iq","attrs":{"type":"result"},"content":[{"tag":"usync","attrs":{},"content":[{"tag":"list","attrs":{},"content":[{"tag":"user","attrs":{"jid":"real@s.whatsapp.net"},"content":[{"tag":"custom","attrs":{}},{"tag":"id","attrs":{}}]}]}]}]})).unwrap();
    let result = q.parse(Some(&response)).unwrap().unwrap();
    assert_eq!(result.list[0].data["custom"], 2);
    assert_eq!(result.list[0].id, "real@s.whatsapp.net");
    assert!(!result.list[0].data.contains_key("id"));
}
#[derive(Clone)]
struct Echo {
    nodes: Arc<Mutex<Vec<Node>>>,
    response: Node,
    fail: bool,
}
impl rustleys_whatsapp::prekeys::Query for Echo {
    async fn query(&self, n: Node) -> rustleys_whatsapp::socket::Result<Arc<Node>> {
        self.nodes.lock().unwrap().push(n);
        if self.fail {
            Err(rustleys_whatsapp::socket::Error::Closed)
        } else {
            Ok(Arc::new(self.response.clone()))
        }
    }
}
#[tokio::test]
async fn async_contact_and_lid_helpers_skip_lids_normalize_phone_and_filter_results() {
    let endpoint = Echo {
        nodes: Default::default(),
        response: node(&fixture()["results"][0]["node"]).unwrap(),
        fail: false,
    };
    let client = usync::Client::new(endpoint.clone()).unwrap();
    assert_eq!(
        client.on_whatsapp(&["999@lid".into()]).await.unwrap(),
        Some(vec![])
    );
    assert!(
        client
            .pn_from_lid(&["999@lid".into()])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(endpoint.nodes.lock().unwrap().is_empty());
    let contacts = client
        .on_whatsapp(&["+5511999999999:4@s.whatsapp.net".into(), "999@lid".into()])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(contacts.len(), 2);
    assert!(contacts.iter().all(|c| c.exists));
    let maps = client
        .pn_from_lid(&["123@s.whatsapp.net".into(), "999@lid".into()])
        .await
        .unwrap();
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].pn, "123@s.whatsapp.net");
    assert_eq!(maps[0].lid, "999@lid");
    let nodes = endpoint.nodes.lock().unwrap();
    let request = &nodes[0];
    let child = |n: &Node| match &n.content {
        Some(Content::Nodes(c)) => c.clone(),
        _ => vec![],
    };
    let usync = &child(request)[0];
    let list = &child(usync)[1];
    let user = &child(list)[0];
    assert!(user.attrs.is_empty());
    assert_eq!(
        child(user)[0].content,
        Some(Content::Text("+5511999999999".into()))
    );
}
#[tokio::test]
async fn cloned_clients_reserve_unique_sids_and_invalid_queries_never_send() {
    let endpoint = Echo {
        nodes: Default::default(),
        response: node(&json!({"tag":"iq","attrs":{"type":"result"}})).unwrap(),
        fail: false,
    };
    let client = usync::Client::new(endpoint.clone()).unwrap();
    assert!(matches!(
        client.execute(&Query::default()).await,
        Err(usync::Error::NoProtocols)
    ));
    assert!(endpoint.nodes.lock().unwrap().is_empty());
    let mut tasks = vec![];
    for _ in 0..32 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            c.execute(&Query::default().with_protocol(Builtin::Devices))
                .await
                .unwrap()
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    {
        let nodes = endpoint.nodes.lock().unwrap();
        let ids = nodes
            .iter()
            .map(|n| {
                let Some(Content::Nodes(c)) = &n.content else {
                    panic!()
                };
                c[0].attrs
                    .iter()
                    .find(|(k, _)| k == "sid")
                    .unwrap()
                    .1
                    .clone()
            })
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), 32);
    }
    let failing = usync::Client::new(Echo {
        fail: true,
        ..endpoint
    })
    .unwrap();
    assert!(matches!(
        failing
            .execute(&Query::default().with_protocol(Builtin::Contact))
            .await,
        Err(usync::Error::Network(_))
    ));
}

#[test]
fn repeated_protocols_stop_building_before_expanding_the_whole_request() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Count(Arc<AtomicUsize>);
    impl Protocol for Count {
        fn name(&self) -> &str {
            "count"
        }
        fn query_element(&self) -> Node {
            Node {
                tag: "count".into(),
                attrs: vec![],
                content: None,
            }
        }
        fn user_element(&self, _: &User) -> Option<Node> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Some(Node {
                tag: "count".into(),
                attrs: vec![],
                content: Some(Content::Text("x".repeat(100))),
            })
        }
        fn parse(&self, _: &Node) -> usync::Result<Option<Value>> {
            Ok(None)
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let mut q = Query::default().with_user(User::default().with_id("1@s.whatsapp.net"));
    for _ in 0..32 {
        q = q.with_protocol(Count(calls.clone()));
    }
    q.limits.max_bytes = 300;
    assert!(matches!(q.build("test"), Err(usync::Error::Limit)));
    assert!(calls.load(Ordering::SeqCst) < 4);
}

#[test]
fn only_explicitly_registered_protocols_run_not_inherited_javascript_object_members() {
    for row in fixture()["differences"].as_array().unwrap() {
        let result = config(&row["config"])
            .parse(Some(&node(&row["node"]).unwrap()))
            .unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), row["native"]);
    }
}

#[test]
fn registered_parser_names_are_snapshotted_before_processing_any_response_fields() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Changing(Arc<AtomicUsize>);
    impl Protocol for Changing {
        fn name(&self) -> &str {
            if self.0.load(Ordering::SeqCst) == 0 {
                "first"
            } else {
                "changed"
            }
        }
        fn query_element(&self) -> Node {
            Node {
                tag: "first".into(),
                attrs: vec![],
                content: None,
            }
        }
        fn user_element(&self, _: &User) -> Option<Node> {
            None
        }
        fn parse(&self, _: &Node) -> usync::Result<Option<Value>> {
            Ok(Some(json!(self.0.fetch_add(1, Ordering::SeqCst) + 1)))
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let q = Query::default().with_protocol(Changing(calls.clone()));
    let response=node(&json!({"tag":"iq","attrs":{"type":"result"},"content":[{"tag":"usync","attrs":{},"content":[{"tag":"list","attrs":{},"content":[{"tag":"user","attrs":{"jid":"1@s.whatsapp.net"},"content":[{"tag":"first","attrs":{}},{"tag":"first","attrs":{}}]}]}]}]})).unwrap();
    let result = q.parse(Some(&response)).unwrap().unwrap();
    assert_eq!(result.list[0].data["first"], 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
