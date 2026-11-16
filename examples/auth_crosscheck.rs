//! Offline synthetic interoperability driver; do not point at real auth folders.
use rustleys_whatsapp::{
    auth::Credentials,
    auth_store::{Category, KeySet, MultiFileStore},
};
use std::collections::BTreeMap;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("expected synthetic input and output folders".into());
    }
    let source = MultiFileStore::open(&args[1])?;
    let target = MultiFileStore::open(&args[2])?;
    let creds = source
        .load_credentials()?
        .ok_or("missing synthetic credentials")?;
    target.save_credentials(&creds)?;
    let mut data: KeySet = BTreeMap::new();
    for category in [
        Category::PreKey,
        Category::Session,
        Category::SenderKey,
        Category::SenderKeyMemory,
        Category::AppStateSyncKey,
        Category::AppStateSyncVersion,
        Category::LidMapping,
        Category::DeviceList,
        Category::TcToken,
        Category::IdentityKey,
    ] {
        data.insert(category, source.get(category, &["synthetic/1:2".into()])?);
    }
    target.set(&data)?;
    let fresh = MultiFileStore::open(std::path::Path::new(&args[2]).join("fresh"))?;
    fresh.save_credentials(&Credentials::generate()?)?;
    println!(
        "Copied synthetic credentials and 10 key categories; generated fresh Rust credentials"
    );
    Ok(())
}
