//! Offline USync oracle driver; no live account or server.
use rustleys_whatsapp::{
    binary::{Content, Node},
    usync::{Builtin, Protocol, Query, User},
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

fn config(v: &Value) -> Result<Query, Box<dyn std::error::Error>> {
    let mut q = Query::default();
    for p in v["protocols"].as_array().ok_or("protocols")? {
        q = q.with_protocol(serde_json::from_value::<Builtin>(p.clone())?);
    }
    q.users = serde_json::from_value::<Vec<User>>(v["users"].clone())?;
    if let Some(mode) = v["mode"].as_str() {
        q.mode = mode.into();
    }
    if let Some(context) = v["context"].as_str() {
        q.context = context.into();
    }
    Ok(q)
}
async fn execute(request: Value) -> Result<Value, Box<dyn std::error::Error>> {
    match request["command"].as_str().ok_or("command")? {
        "execute" | "on_whatsapp" | "pn_from_lid" => {
            let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let endpoint = Echo {
                requests: requests.clone(),
                response: node(&request["response"])?,
            };
            let client = rustleys_whatsapp::usync::Client::new(endpoint)?;
            let value = match request["command"].as_str().unwrap() {
                "execute" => {
                    serde_json::to_value(client.execute(&config(&request["config"])?).await?)?
                }
                "on_whatsapp" => serde_json::to_value(
                    client
                        .on_whatsapp(&serde_json::from_value::<Vec<String>>(
                            request["phones"].clone(),
                        )?)
                        .await?,
                )?,
                _ => serde_json::to_value(
                    client
                        .pn_from_lid(&serde_json::from_value::<Vec<String>>(
                            request["jids"].clone(),
                        )?)
                        .await?,
                )?,
            };
            let requests = requests.lock().unwrap();
            let wire = requests
                .iter()
                .map(rustleys_whatsapp::binary::encode)
                .collect::<Result<Vec<_>, _>>()?;
            let sids = requests
                .iter()
                .map(|n| match &n.content {
                    Some(Content::Nodes(c)) => c[0]
                        .attrs
                        .iter()
                        .find(|(k, _)| k == "sid")
                        .map(|(_, v)| v.clone())
                        .unwrap(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>();
            Ok(json!({"value":value,"wire":wire,"sids":sids}))
        }
        "build" => Ok(json!(rustleys_whatsapp::binary::encode(
            &config(&request["config"])?.build(request["sid"].as_str().ok_or("sid")?)?
        )?)),
        "parse" => Ok(serde_json::to_value(
            config(&request["config"])?.parse(Some(&node(&request["node"])?))?,
        )?),
        "protocol" => Ok(
            serde_json::from_value::<Builtin>(request["protocol"].clone())?
                .parse(&node(&request["node"])?)?
                .unwrap_or(Value::Null),
        ),
        _ => Err("unknown command".into()),
    }
}
#[derive(Clone)]
struct Echo {
    requests: std::sync::Arc<std::sync::Mutex<Vec<Node>>>,
    response: Node,
}
impl rustleys_whatsapp::prekeys::Query for Echo {
    async fn query(&self, n: Node) -> rustleys_whatsapp::socket::Result<std::sync::Arc<Node>> {
        self.requests.lock().unwrap().push(n);
        Ok(std::sync::Arc::new(self.response.clone()))
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let result = match line {
            Ok(line) => match serde_json::from_str(&line) {
                Ok(request) => execute(request).await,
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        };
        let response = match result {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
