//! Offline synthetic oracle; explicit private-key exports are test data only.
use rustleys_whatsapp::{
    auth::{Credentials, KeyPair},
    prekeys::Manager,
    signal::{MessageType, Repository, SqliteStore},
};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Write},
    sync::Arc,
};
fn execute(path: &str, request: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let creds = Credentials::from_json(&serde_json::to_vec(&request["credentials"])?)?;
    let store = Arc::new(SqliteStore::open(path)?);
    let repo = Repository::new(&creds, store.clone())?;
    match request["command"].as_str().ok_or("command required")? {
        "prepare" => {
            if let Some(keys) = request["keys"].as_object() {
                for (id, pair) in keys {
                    let pair: KeyPair = serde_json::from_value(pair.clone())?;
                    repo.put_pre_key(id.parse()?, &pair)?;
                }
            }
            let manager = Manager::new(&creds, store)?;
            let prepared = manager.prepare(serde_json::from_value(request["count"].clone())?)?;
            let keys = manager.get_pre_keys(prepared.first, prepared.first + prepared.count)?;
            Ok(
                json!({"wire":rustleys_whatsapp::binary::encode(&prepared.node)?,"update":prepared.counters,"keys":keys}),
            )
        }
        "decrypt" => {
            let bytes: Vec<u8> = serde_json::from_value(request["ciphertext"].clone())?;
            let plaintext = repo.decrypt(
                "synthetic-peer:1@s.whatsapp.net",
                MessageType::PreKey,
                &bytes,
            )?;
            Ok(json!(plaintext.expose()))
        }
        "has" => Ok(json!(
            repo.has_pre_key(serde_json::from_value(request["id"].clone())?)?
        )),
        _ => Err("unknown command".into()),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("synthetic database required")?;
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(Into::into)
            .and_then(|line| Ok(serde_json::from_str(&line)?))
            .and_then(|request| execute(&path, request));
        let response = match result {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
