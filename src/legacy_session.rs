//! Bounded, fail-closed import of libsignal-node v6 session JSON.
//! This converts data formats; no JavaScript cryptographic implementation is ported.
use crate::signal::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use serde::{
    Deserialize,
    de::{MapAccess, Visitor},
};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};
use wacore_libsignal::engine::{
    Chain, MessageKey, PendingPreKey, RustCrypto, SessionMetadata, SessionRecord, SessionState,
    codec, wire,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_LEGACY_SESSION_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHAINS: usize = 1024;
const MAX_KEYS: usize = 32_768;

#[derive(Deserialize)]
#[serde(transparent)]
struct Secret(String);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Serde's ordinary map deserializer silently replaces duplicate keys. Reject
// those instead: silently choosing either counter/key can resurrect old state.
fn unique<'de, D, T>(deserializer: D) -> std::result::Result<Vec<(String, T)>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Unique<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Unique<T> {
        type Value = Vec<(String, T)>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("unique object keys")
        }
        fn visit_map<M: MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut seen = HashSet::new();
            let mut result = Vec::new();
            while let Some((key, value)) = map.next_entry::<String, T>()? {
                if !seen.insert(key.clone()) {
                    return Err(serde::de::Error::custom("duplicate key"));
                }
                result.push((key, value));
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyRecord {
    version: Option<String>,
    registration_id: Option<u32>,
    #[serde(rename = "_sessions", default, deserialize_with = "unique")]
    sessions: Vec<(String, Entry)>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    registration_id: Option<u32>,
    current_ratchet: Ratchet,
    index_info: Index,
    #[serde(rename = "_chains", deserialize_with = "unique")]
    chains: Vec<(String, LegacyChain)>,
    pending_pre_key: Option<Pending>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pair {
    pub_key: Secret,
    priv_key: Secret,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ratchet {
    ephemeral_key_pair: Pair,
    last_remote_ephemeral_key: Secret,
    previous_counter: i64,
    root_key: Secret,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    base_key: Secret,
    base_key_type: u8,
    closed: i64,
    used: i64,
    created: i64,
    remote_identity_key: Secret,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyChain {
    chain_key: ChainKey,
    chain_type: u8,
    #[serde(deserialize_with = "unique")]
    message_keys: Vec<(String, Secret)>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainKey {
    counter: i64,
    key: Option<Secret>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    base_key: Secret,
    signed_key_id: u32,
    pre_key_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImportReport {
    pub open_sessions: usize,
    pub archived_sessions: usize,
    pub receiving_chains: usize,
    pub skipped_message_keys: usize,
}
fn invalid() -> Error {
    Error::InvalidLegacySession
}
fn raw<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(STANDARD.decode(text).map_err(|_| invalid())?);
    // Standard padded base64 is the source format. Reject aliases/noncanonical tails.
    if Zeroizing::new(STANDARD.encode(&*bytes)).as_str() != text {
        return Err(invalid());
    }
    bytes.as_slice().try_into().map_err(|_| invalid())
}
fn public(text: &str) -> Result<[u8; 32]> {
    let tagged = raw::<33>(text)?;
    wire::decode_public(&tagged).map_err(|_| invalid())
}
fn timestamp(value: i64) -> bool {
    (0..=9_007_199_254_740_991).contains(&value)
}
fn state(
    entry: &Entry,
    local: [u8; 32],
    registration: u32,
    fallback: Option<u32>,
    budget: &mut usize,
) -> Result<SessionState> {
    if entry.chains.len() > MAX_CHAINS
        || !timestamp(entry.index_info.used)
        || !timestamp(entry.index_info.created)
        || (entry.index_info.closed != -1 && !timestamp(entry.index_info.closed))
        || !matches!(entry.index_info.base_key_type, 1 | 2)
    {
        return Err(invalid());
    }
    let pair = &entry.current_ratchet.ephemeral_key_pair;
    let private = Zeroizing::new(raw::<32>(&pair.priv_key.0)?);
    let sender_key = public(&pair.pub_key.0)?;
    if crate::crypto::PrivateKey::from_bytes(*private).public_key() != sender_key {
        return Err(invalid());
    }
    let last_remote = public(&entry.current_ratchet.last_remote_ephemeral_key.0)?;
    let base = public(&entry.index_info.base_key.0)?;
    let mut sender = None;
    let mut receivers = Vec::new();
    let mut known = HashSet::new();
    for (ratchet, chain) in &entry.chains {
        let ratchet = public(ratchet)?;
        if !known.insert(ratchet) || !(-1..i64::from(u32::MAX)).contains(&chain.chain_key.counter) {
            return Err(invalid());
        }
        let index = (chain.chain_key.counter + 1) as u32;
        *budget = budget
            .checked_add(chain.message_keys.len())
            .ok_or_else(invalid)?;
        if *budget > MAX_KEYS {
            return Err(Error::TooLarge);
        }
        let mut skipped = VecDeque::new();
        let mut counters = HashSet::new();
        for (counter, seed) in &chain.message_keys {
            let counter_u32 = counter.parse::<u32>().map_err(|_| invalid())?;
            if counter_u32.to_string() != *counter
                || counter_u32 >= index
                || !counters.insert(counter_u32)
            {
                return Err(invalid());
            }
            skipped.push_back(MessageKey::Seed {
                index: counter_u32,
                seed: raw(&seed.0)?,
            });
        }
        let key = chain
            .chain_key
            .key
            .as_ref()
            .map(|s| raw::<32>(&s.0))
            .transpose()?;
        let native = Chain {
            ratchet,
            private: if chain.chain_type == 1 {
                Some(*private)
            } else {
                None
            },
            index,
            key: key.unwrap_or([0; 32]),
            exhausted: key.is_none(),
            skipped: skipped.into(),
            message_key_limit: Some(MAX_KEYS as u32),
        };
        match chain.chain_type {
            1 if sender.is_none()
                && ratchet == sender_key
                && key.is_some()
                && chain.message_keys.is_empty() =>
            {
                sender = Some(native)
            }
            2 => receivers.push(native),
            _ => return Err(invalid()),
        }
    }
    // Persisted JS entries have a sending chain. An incoming half-handshake is
    // transient and cannot safely be resumed as a stored session.
    if sender.is_none() {
        return Err(invalid());
    }
    // Keep the most recent receiving chain last without discarding older keys.
    if let Some(position) = receivers.iter().position(|c| c.ratchet == last_remote) {
        let latest = receivers.remove(position);
        receivers.push(latest);
    } else if !receivers.is_empty() {
        return Err(invalid());
    }
    let pending = entry
        .pending_pre_key
        .as_ref()
        .map(|pending| {
            let pending_base = public(&pending.base_key.0)?;
            if pending_base != base
                || entry.index_info.base_key_type != 1
                || pending.signed_key_id > i32::MAX as u32
            {
                return Err(invalid());
            }
            Ok(Arc::new(PendingPreKey {
                pre_key_id: pending.pre_key_id,
                signed_pre_key_id: Some(pending.signed_key_id as i32),
                base_key: pending_base,
                kyber_pre_key_id: None,
                kyber_ciphertext: None,
            }))
        })
        .transpose()?;
    let previous = entry.current_ratchet.previous_counter;
    if !(-1..=i64::from(u32::MAX)).contains(&previous) {
        return Err(invalid());
    }
    Ok(SessionState {
        metadata: Arc::new(SessionMetadata {
            version: 3,
            local_identity: local,
            remote_identity: public(&entry.index_info.remote_identity_key.0)?,
            root: raw(&entry.current_ratchet.root_key.0)?,
            previous_counter: previous as u32,
            local_registration: registration,
            remote_registration: entry.registration_id.or(fallback).ok_or_else(invalid)?,
            needs_refresh: false,
            alice_base_key: Some(base),
            alice_base_key_tagged: true,
            pending_key_exchange: None,
        }),
        sender,
        receivers,
        pending_pre_key: pending,
    })
}
#[derive(Message)]
struct RecordEnvelope {
    #[prost(bytes = "vec", optional, tag = "1")]
    current: Option<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    previous: Vec<Vec<u8>>,
}
impl Drop for RecordEnvelope {
    fn drop(&mut self) {
        if let Some(bytes) = &mut self.current {
            bytes.zeroize();
        }
        for bytes in &mut self.previous {
            bytes.zeroize();
        }
    }
}
/// Host must supply the same local identity/registration used by the old store.
/// JSON does not contain a local identity, so this relationship cannot be proved
/// from the imported file alone. No cryptographic session is replaced here.
pub(crate) fn decode(
    input: &[u8],
    local: [u8; 32],
    registration: u32,
) -> Result<(SessionRecord, ImportReport)> {
    if input.len() > MAX_LEGACY_SESSION_BYTES {
        return Err(Error::TooLarge);
    }
    let legacy: LegacyRecord = serde_json::from_slice(input).map_err(|_| invalid())?;
    if legacy.version.as_deref().is_some_and(|v| v != "v1") || legacy.sessions.len() > 41 {
        return Err(invalid());
    }
    let fallback = if legacy.version.is_none() {
        legacy.registration_id
    } else {
        None
    };
    let mut envelope = RecordEnvelope {
        current: None,
        previous: Vec::new(),
    };
    let mut budget = 0;
    let mut report = ImportReport {
        open_sessions: 0,
        archived_sessions: 0,
        receiving_chains: 0,
        skipped_message_keys: 0,
    };
    let mut archived = Vec::new();
    let mut bases = HashSet::new();
    for (base, entry) in &legacy.sessions {
        if public(base)? != public(&entry.index_info.base_key.0)? || !bases.insert(public(base)?) {
            return Err(invalid());
        }
        let state = state(entry, local, registration, fallback, &mut budget)?;
        report.receiving_chains += state.receivers.len();
        let mut bytes = Zeroizing::new(codec::encode_session_state(&state));
        if entry.index_info.closed == -1 {
            if envelope.current.is_some() {
                return Err(invalid());
            }
            envelope.current = Some(std::mem::take(&mut *bytes));
            report.open_sessions += 1;
        } else {
            archived.push((entry.index_info.used, bytes));
            report.archived_sessions += 1;
        }
    }
    if archived.len() > 40 {
        return Err(invalid());
    }
    archived.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    envelope.previous = archived
        .into_iter()
        .map(|(_, mut b)| std::mem::take(&mut *b))
        .collect();
    report.skipped_message_keys = budget;
    // The temporary serialized states contain secrets, just like the input.
    let encoded = Zeroizing::new(envelope.encode_to_vec());
    if let Some(bytes) = &mut envelope.current {
        bytes.zeroize();
    }
    for bytes in &mut envelope.previous {
        bytes.zeroize();
    }
    Ok((codec::decode_session_record(&RustCrypto, &encoded)?, report))
}
