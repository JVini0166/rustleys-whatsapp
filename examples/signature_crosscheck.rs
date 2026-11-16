//! Emits only synthetic signatures from committed, public reference-test keys.
use rustleys_whatsapp::crypto::{PrivateKey, signed_key_pair};
use std::io::Write;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/crypto-upstream.json"))?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for row in fixture["agreements"].as_array().ok_or("missing cases")? {
        let bytes = |name: &str| {
            row[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
        };
        let key = PrivateKey::from_bytes(bytes("privateKey").try_into().map_err(|_| "key length")?);
        let message = bytes("message");
        let prekey = signed_key_pair(&key, 42)?;
        serde_json::to_writer(
            &mut out,
            &serde_json::json!({"signature":key.sign(&message)?.as_slice(),"prekeyPublic":prekey.public_key,"prekeySignature":prekey.signature.as_slice()}),
        )?;
        writeln!(&mut out)?;
    }
    Ok(())
}
