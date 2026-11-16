//! JSON-lines driver for offline synthetic libsignal-node interoperability only.
use rustleys_whatsapp::{
    auth::{Credentials, KeyPair},
    signal::{MessageType, PreKeyBundle, PublicSignedPreKey, Repository, SqliteStore},
};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use wacore_libsignal::engine::wire;
fn bytes(v: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(v.clone())?)
}
fn public(v: &Value) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(wire::decode_public(&bytes(v)?)?)
}
fn execute(
    repo: &mut Option<Repository<SqliteStore>>,
    path: &str,
    request: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    if request["command"] == "configure" {
        let creds = Credentials::from_json(&serde_json::to_vec(&request["credentials"])?)?;
        *repo = Some(Repository::new(&creds, SqliteStore::open(path)?)?);
        return Ok(json!(true));
    }
    let repo = repo.as_ref().ok_or("configure first")?;
    let jid = request["jid"].as_str().unwrap_or("");
    Ok(
        match request["command"].as_str().ok_or("missing command")? {
            "group_distribution" => {
                let group = request["group"].as_str().ok_or("group required")?;
                let author = request["author"].as_str().ok_or("author required")?;
                json!(repo.sender_key_distribution(group, author)?.expose())
            }
            "group_process" => {
                repo.process_sender_key_distribution(
                    request["group"].as_str().ok_or("group required")?,
                    request["author"].as_str().ok_or("author required")?,
                    &bytes(&request["distribution"])?,
                )?;
                json!(true)
            }
            "group_encrypt" => {
                let encrypted = repo.encrypt_group_message(
                    request["group"].as_str().ok_or("group required")?,
                    request["author"].as_str().ok_or("author required")?,
                    &bytes(&request["plaintext"])?,
                )?;
                json!({"ciphertext":encrypted.ciphertext,"distribution":encrypted.sender_key_distribution.expose()})
            }
            "group_decrypt" => json!(
                repo.decrypt_group_message(
                    request["group"].as_str().ok_or("group required")?,
                    request["author"].as_str().ok_or("author required")?,
                    &bytes(&request["ciphertext"])?
                )?
                .expose()
            ),
            "group_has" => json!(repo.has_sender_key(
                request["group"].as_str().ok_or("group required")?,
                request["author"].as_str().ok_or("author required")?
            )?),
            "group_delete" => {
                repo.delete_sender_key(
                    request["group"].as_str().ok_or("group required")?,
                    request["author"].as_str().ok_or("author required")?,
                )?;
                json!(true)
            }
            "put_prekey" => {
                let key: KeyPair = serde_json::from_value(request["key"].clone())?;
                repo.put_pre_key(serde_json::from_value(request["id"].clone())?, &key)?;
                json!(true)
            }
            "has_prekey" => {
                json!(repo.has_pre_key(serde_json::from_value(request["id"].clone())?)?)
            }
            "inject" => {
                let b = &request["bundle"];
                let one_time = if b["preKey"].is_null() {
                    None
                } else {
                    Some((
                        serde_json::from_value(b["preKey"]["keyId"].clone())?,
                        public(&b["preKey"]["publicKey"])?,
                    ))
                };
                let bundle = PreKeyBundle {
                    registration_id: serde_json::from_value(b["registrationId"].clone())?,
                    identity: public(&b["identityKey"])?,
                    signed_pre_key: PublicSignedPreKey {
                        id: serde_json::from_value(b["signedPreKey"]["keyId"].clone())?,
                        public: public(&b["signedPreKey"]["publicKey"])?,
                        signature: bytes(&b["signedPreKey"]["signature"])?
                            .try_into()
                            .map_err(|_| "signature length")?,
                    },
                    one_time_pre_key: one_time,
                };
                repo.inject_session(jid, &bundle)?;
                json!(true)
            }
            "encrypt" => {
                let encrypted = repo.encrypt(jid, &bytes(&request["plaintext"])?)?;
                json!({"type":encrypted.kind.as_str(),"ciphertext":encrypted.bytes})
            }
            "decrypt" => {
                let kind = match request["type"].as_str() {
                    Some("pkmsg") => MessageType::PreKey,
                    Some("msg") => MessageType::Normal,
                    _ => return Err("unknown message type".into()),
                };
                json!(
                    repo.decrypt(jid, kind, &bytes(&request["ciphertext"])?)?
                        .expose()
                )
            }
            "info" => match repo.session_info(jid)? {
                None => Value::Null,
                Some(info) => {
                    json!({"baseKey":info.base_key.to_vec(),"registrationId":info.registration_id})
                }
            },
            "delete" => {
                repo.delete_sessions(&[jid.into()])?;
                json!(true)
            }
            _ => return Err("unknown command".into()),
        },
    )
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("synthetic SQLite path required")?;
    let mut repo = None;
    for line in io::stdin().lock().lines() {
        let response = match line
            .map_err(Into::into)
            .and_then(|line| Ok(serde_json::from_str::<Value>(&line)?))
            .and_then(|request| execute(&mut repo, &path, request))
        {
            Ok(value) => json!({"ok":true,"value":value}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        };
        println!("{response}");
        io::stdout().flush()?;
    }
    Ok(())
}
