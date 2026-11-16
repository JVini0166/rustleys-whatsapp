//! Transactional group sender-key operations compatible with Baileys' v3 wire.
//! Sender distribution bytes contain a secret chain seed: transmit them only
//! through the authenticated E2EE distribution flow, never in plaintext logs.
use crate::{
    auth::Bytes,
    signal::{
        Error, MAX_MESSAGE, OsRandom, Repository, Result, Store, Transaction, protocol_address,
    },
};
use subtle::ConstantTimeEq;
use wacore_libsignal::engine::{self, CryptoProvider, Engine, RustCrypto, codec, wire};
use zeroize::Zeroizing;

/// Typed equivalent of SenderKeyName for standard Signal protocol addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SenderKeyName {
    group: String,
    sender: String,
    device: u32,
}
impl SenderKeyName {
    pub fn new(group: impl Into<String>, sender: impl Into<String>, device: u32) -> Self {
        Self {
            group: group.into(),
            sender: sender.into(),
            device,
        }
    }
    pub fn group_id(&self) -> &str {
        &self.group
    }
    pub fn sender_id(&self) -> &str {
        &self.sender
    }
    pub fn device_id(&self) -> u32 {
        self.device
    }
    pub fn sender_address(&self) -> String {
        format!("{}.{}", self.sender, self.device)
    }
    pub fn serialize(&self) -> String {
        self.to_string()
    }
    pub fn equals(&self, other: Option<&Self>) -> bool {
        other == Some(self)
    }
    pub fn hash_code(&self) -> i32 {
        fn java_hash(s: &str) -> i32 {
            s.encode_utf16().fold(0_i32, |hash, c| {
                hash.wrapping_mul(31).wrapping_add(i32::from(c))
            })
        }
        java_hash(&self.group) ^ java_hash(&self.sender_address())
    }
}
impl std::fmt::Display for SenderKeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}::{}", self.group, self.sender, self.device)
    }
}

pub fn sender_key_name(group: &str, author: &str) -> Result<String> {
    if group.is_empty() {
        return Err(Error::InvalidGroup);
    }
    let address = protocol_address(author)?;
    let (name, device) = address.rsplit_once('.').ok_or(Error::InvalidAddress)?;
    Ok(format!("{group}::{name}::{device}"))
}
#[derive(Debug)]
pub struct GroupCiphertext {
    pub ciphertext: Vec<u8>,
    pub sender_key_distribution: Bytes,
}
impl GroupCiphertext {
    /// Explicitly exports the secret distribution payload for E2EE transport.
    pub fn distribution_message(
        &self,
        group: &str,
    ) -> Result<crate::proto::message::SenderKeyDistributionMessage> {
        if group.is_empty() {
            return Err(Error::InvalidGroup);
        }
        Ok(crate::proto::message::SenderKeyDistributionMessage {
            group_id: Some(group.into()),
            axolotl_sender_key_distribution_message: Some(
                self.sender_key_distribution.expose().to_vec(),
            ),
        })
    }
}
fn load(tx: &mut dyn Transaction, name: &str) -> Result<engine::SenderKeyRecord> {
    tx.get("sender-key", name)?
        .map(|bytes| codec::decode_sender_key_record(&RustCrypto, &bytes).map_err(Into::into))
        .transpose()
        .map(|v| v.unwrap_or_default())
}
fn save(tx: &mut dyn Transaction, name: &str, record: &engine::SenderKeyRecord) -> Result<()> {
    let bytes = Zeroizing::new(codec::encode_sender_key_record(record));
    tx.put("sender-key", name, &bytes)
}
fn distribution(record: &mut engine::SenderKeyRecord) -> Result<Vec<u8>> {
    if record.states.is_empty() {
        let encoded = Engine::new(&RustCrypto, &mut OsRandom).create_sender_distribution(record)?;
        // crypto.randomInt(2147483647) in Baileys excludes the upper bound.
        if record.states[0].id != 0x7fff_ffff {
            return Ok(encoded);
        }
        let _discarded = Zeroizing::new(encoded);
        while record.states[0].id == 0x7fff_ffff {
            let mut bytes = [0; 4];
            engine::RandomSource::fill(&mut OsRandom, &mut bytes)?;
            record.states[0].id = u32::from_le_bytes(bytes) & 0x7fff_ffff;
        }
    }
    let state = &record.states[0];
    Ok(wire::SenderKeyDistribution {
        id: state.id,
        iteration: state.iteration,
        chain_key: state.chain_key,
        signing_key: state.signing_public,
    }
    .encode())
}
/// The pinned GroupCipher requests current iteration + 1 after its first send,
/// retaining the skipped seed. Preserve this observable 0,2,4... progression.
fn advance_baileys_sender(record: &mut engine::SenderKeyRecord) -> Result<()> {
    let state = record.states.first_mut().ok_or(engine::Error::MissingKey)?;
    if state.signing_private.is_none() {
        return Err(engine::Error::MissingKey.into());
    }
    if state.iteration != 0 {
        skip_step(state)?;
    }
    Ok(())
}
fn skip_step(state: &mut engine::SenderKeyState) -> Result<()> {
    let next = state
        .iteration
        .checked_add(1)
        .ok_or(engine::Error::CounterExhausted)?;
    let (seed, key) = RustCrypto.chain_step(&state.chain_key)?;
    state.skipped.push_back(engine::SenderMessageKey {
        iteration: state.iteration,
        seed,
    });
    while state.skipped.len() > engine::MAX_SKIPPED {
        state.skipped.pop_front();
    }
    state.chain_key = key;
    state.iteration = next;
    Ok(())
}
/// The caller must authenticate the sender/distribution with the pairwise
/// envelope before calling this API. A fresh trusted distribution can resume a
/// chain beyond the normal bounded message gap, without reviving consumed keys.
fn merge_distribution(record: &mut engine::SenderKeyRecord, input: &[u8]) -> Result<()> {
    let incoming = wire::SenderKeyDistribution::decode(input)?;
    let Some(index) = record
        .states
        .iter()
        .position(|state| state.id == incoming.id && state.signing_public == incoming.signing_key)
    else {
        Engine::new(&RustCrypto, &mut OsRandom).process_sender_distribution(record, input)?;
        return Ok(());
    };
    let mut state = record.states.remove(index);
    if incoming.iteration > state.iteration {
        let gap = incoming.iteration - state.iteration;
        if gap <= engine::PEER_FUTURE_LIMIT {
            while state.iteration < incoming.iteration {
                skip_step(&mut state)?;
            }
            if !bool::from(state.chain_key.ct_eq(&incoming.chain_key)) {
                return Err(engine::Error::Authentication.into());
            }
        } else {
            // Do not hash through an unbounded backlog. The authenticated
            // distribution supplies the new seed; already-retained skipped keys
            // stay available, while the unmaterialized middle gap is abandoned.
            state.chain_key = incoming.chain_key;
            state.iteration = incoming.iteration;
        }
    }
    record.states.retain(|state| state.id != incoming.id);
    record.states.insert(0, state);
    record.states.truncate(engine::MAX_SENDER_STATES);
    record.reservation.reset_chain();
    Ok(())
}

impl<S: Store> Repository<S> {
    pub fn has_sender_key(&self, group: &str, author: &str) -> Result<bool> {
        let name = sender_key_name(group, author)?;
        self.store
            .transaction(|tx| Ok(tx.get("sender-key", &name)?.is_some()))
    }
    pub fn sender_key_distribution(&self, group: &str, author: &str) -> Result<Bytes> {
        let name = sender_key_name(group, author)?;
        self.store.transaction(|tx| {
            let mut record = load(tx, &name)?;
            let created = record.states.is_empty();
            let bytes = Bytes::new(distribution(&mut record)?);
            if created {
                save(tx, &name, &record)?;
            }
            Ok(bytes)
        })
    }
    /// Typed Message.SenderKeyDistributionMessage entry point. The author and
    /// group membership must already be authenticated by the surrounding flow.
    pub fn process_sender_key_distribution_message(
        &self,
        item: &crate::proto::message::SenderKeyDistributionMessage,
        author: &str,
    ) -> Result<()> {
        let group = item
            .group_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or(Error::InvalidGroup)?;
        let bytes = item
            .axolotl_sender_key_distribution_message
            .as_deref()
            .ok_or(engine::Error::MissingKey)?;
        self.process_sender_key_distribution(group, author, bytes)
    }
    /// Accept only a distribution authenticated from `author` through the
    /// pairwise envelope. Distribution bytes are not self-authenticating.
    /// A forward refresh may abandon an unmaterialized gap above 2,000 keys;
    /// stale refreshes never roll back the current position or consumed keys.
    pub fn process_sender_key_distribution(
        &self,
        group: &str,
        author: &str,
        input: &[u8],
    ) -> Result<()> {
        if input.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        let name = sender_key_name(group, author)?;
        self.store.transaction(|tx| {
            let mut record = load(tx, &name)?;
            merge_distribution(&mut record, input)?;
            save(tx, &name, &record)
        })
    }
    pub fn encrypt_group_message(
        &self,
        group: &str,
        author: &str,
        plaintext: &[u8],
    ) -> Result<GroupCiphertext> {
        if plaintext.len() > MAX_MESSAGE - 1024 {
            return Err(Error::TooLarge);
        }
        let name = sender_key_name(group, author)?;
        self.store.transaction(|tx| {
            let mut record = load(tx, &name)?;
            let sender_key_distribution = Bytes::new(distribution(&mut record)?);
            // The decoder burns any untrusted reservation horizon first. A
            // full transaction per message now guarantees commit before output.
            record.reservation.waive();
            advance_baileys_sender(&mut record)?;
            let ciphertext = Engine::new(&RustCrypto, &mut OsRandom)
                .encrypt_sender_key(&mut record, plaintext)?;
            save(tx, &name, &record)?;
            Ok(GroupCiphertext {
                ciphertext,
                sender_key_distribution,
            })
        })
    }
    pub fn decrypt_group_message(
        &self,
        group: &str,
        author: &str,
        ciphertext: &[u8],
    ) -> Result<Bytes> {
        if ciphertext.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        let name = sender_key_name(group, author)?;
        self.store.transaction(|tx| {
            let mut record = load(tx, &name)?;
            let plaintext = Bytes::new(
                Engine::new(&RustCrypto, &mut OsRandom)
                    .decrypt_sender_key(&mut record, ciphertext)?,
            );
            save(tx, &name, &record)?;
            Ok(plaintext)
        })
    }
    /// Host-side rekeying hook: the next send generates a fresh sender state.
    /// The send layer must distribute that new state to authorized members.
    pub fn delete_sender_key(&self, group: &str, author: &str) -> Result<()> {
        let name = sender_key_name(group, author)?;
        self.store.transaction(|tx| tx.remove("sender-key", &name))
    }
}
