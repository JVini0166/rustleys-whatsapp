//! Offline JSON-lines oracle driver. Use synthetic credentials only.
use prost::Message;
use rustleys_whatsapp::{
    auth::Credentials,
    auth_store::MultiFileStore,
    binary::{Content, Node},
    pairing,
};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
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
fn json_node(node: &Node) -> Value {
    let attrs: serde_json::Map<String, Value> = node
        .attrs
        .iter()
        .map(|(key, value)| (key.clone(), json!(value)))
        .collect();
    json!({"tag":node.tag,"attrs":attrs,"content":match &node.content{None=>Value::Null,Some(Content::Text(text))=>json!(text),Some(Content::Bytes(bytes))=>json!({"bytes":bytes}),Some(Content::Nodes(nodes))=>json!(nodes.iter().map(json_node).collect::<Vec<_>>())}})
}
fn execute(request: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut creds = Credentials::from_json(&serde_json::to_vec(&request["credentials"])?)?;
    match request["command"].as_str().ok_or("command required")? {
        "registration" => Ok(json!(
            pairing::registration_payload(
                &creds,
                &serde_json::from_value(request["config"].clone())?
            )?
            .encode_to_vec()
        )),
        "login" => Ok(json!(
            pairing::login_payload(
                request["jid"].as_str().ok_or("jid required")?,
                &serde_json::from_value(request["config"].clone())?
            )?
            .encode_to_vec()
        )),
        "qr" => {
            let browser = serde_json::from_value(request["browser"].clone())?;
            Ok(json!(
                pairing::pairing_qr_data(
                    request["reference"].as_str().ok_or("reference required")?,
                    &creds,
                    &browser
                )?
                .expose()
            ))
        }
        "pair" => {
            let update = pairing::configure_successful_pairing(&node(&request["stanza"])?, &creds)?;
            let temp = tempfile::tempdir()?;
            let store = MultiFileStore::open(temp.path())?;
            store.save_credentials(&creds)?;
            let reply = update.persist_and_reply(&store, &mut creds)?;
            Ok(
                json!({"reply":json_node(&reply),"wire":rustleys_whatsapp::binary::encode(&reply)?,"credentials":serde_json::from_slice::<Value>(&creds.to_json()?)?}),
            )
        }
        _ => Err("unknown command".into()),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(Into::into)
            .and_then(|line| Ok(serde_json::from_str(&line)?))
            .and_then(execute);
        let response = match result {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
