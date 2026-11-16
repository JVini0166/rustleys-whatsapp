fn normalize_enums(source: &str) -> Result<(String, usize), Box<dyn std::error::Error>> {
    // Baileys' protobuf.js permits non-zero-first proto3 enums. protoc does not.
    // Keep all upstream numbers/names; move an existing zero first or add a
    // namespaced local sentinel. The original schema remains byte-for-byte intact.
    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut changed = 0;
    while i < lines.len() {
        let line = lines[i];
        out.push_str(line);
        out.push('\n');
        i += 1;
        if let Some(rest) = line.trim_start().strip_prefix("enum ") {
            let name = rest.split_whitespace().next().ok_or("missing enum name")?;
            let start = i;
            while i < lines.len() && !lines[i].trim_start().starts_with('}') {
                i += 1;
            }
            if i == lines.len() {
                return Err("unclosed enum".into());
            }
            let body = &lines[start..i];
            let numeric = |s: &str| {
                s.split_once('=')
                    .and_then(|(_, v)| v.trim().split([';', '[']).next())
                    .and_then(|v| v.trim().parse::<i32>().ok())
            };
            let first = body.iter().find_map(|s| numeric(s));
            let zero = body.iter().position(|s| numeric(s) == Some(0));
            if first != Some(0) {
                changed += 1;
                if let Some(zero) = zero {
                    out.push_str(body[zero]);
                    out.push('\n');
                } else {
                    out.push_str(&format!(
                        "        RUSTLEYS_{}_UNSPECIFIED = 0;\n",
                        name.to_uppercase()
                    ));
                }
                for (j, s) in body.iter().enumerate() {
                    if Some(j) != zero {
                        out.push_str(s);
                        out.push('\n');
                    }
                }
            } else {
                for s in body {
                    out.push_str(s);
                    out.push('\n');
                }
            }
        }
    }
    Ok((out, changed))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/WAProto.proto");
    let output = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let original = std::fs::read_to_string("proto/WAProto.proto")?;
    let (normalized, count) = normalize_enums(&original)?;
    std::fs::write(output.join("WAProto.proto"), normalized)?;
    std::fs::write(
        output.join("proto-normalization-count.txt"),
        count.to_string(),
    )?;
    let mut config = prost_build::Config::new();
    // Keep variant payloads out of every inline EmbeddedContent value.
    config.boxed(".proto.EmbeddedContent.content.embeddedMessage");
    config.boxed(".proto.EmbeddedContent.content.embeddedMusic");
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.file_descriptor_set_path(output.join("proto-descriptor.bin"));
    config.compile_protos(&[output.join("WAProto.proto")], &[output])?;
    Ok(())
}
