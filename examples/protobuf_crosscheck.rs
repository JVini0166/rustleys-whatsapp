//! Development-only encoder used by the independent protobuf.js reverse check.
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use std::io::{Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin()
        .take(16 * 1024 * 1024)
        .read_to_string(&mut input)?;
    let cases: serde_json::Value = serde_json::from_str(&input)?;
    let pool = DescriptorPool::decode(rustleys_whatsapp::PROTO_DESCRIPTOR)?;
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    for row in cases.as_array().ok_or("expected test case array")? {
        let name = row["type"].as_str().ok_or("expected type name")?;
        let desc = pool
            .get_message_by_name(name)
            .ok_or("unknown protobuf message")?;
        let json = row["schema_input"].to_string();
        let mut de = serde_json::Deserializer::from_str(&json);
        let message = DynamicMessage::deserialize(desc, &mut de)?;
        serde_json::to_writer(&mut output, &message.encode_to_vec())?;
        writeln!(&mut output)?;
    }
    Ok(())
}
