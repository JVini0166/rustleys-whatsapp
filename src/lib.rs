//! Independent Rust port of Baileys.
//! Initial development: no WhatsApp client is implemented yet.

/// Pinned upstream reference used by the compatibility inventory.
pub const UPSTREAM_COMMIT: &str = "bb0a87e0326ca8f882fe716c7ee42da362f73fc0";

pub mod binary;
pub mod jid;
mod tokens;

pub mod crypto;
/// Generated from the exact pinned Baileys WAProto schema. No JavaScript runtime.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}
pub const PROTO_DESCRIPTOR: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/proto-descriptor.bin"));

pub mod noise;

pub mod auth;

pub mod auth_store;

pub mod signal;

pub mod group_signal;

pub mod lid_mapping;

pub mod session_migration;

pub mod legacy_session;

pub mod socket;

pub mod pairing;

pub mod prekeys;

pub mod signed_keys;
