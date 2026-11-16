//! Native Signal v3 pairwise sessions backed by the pinned wacore engine.
//! Every operation is transactional: state commits before ciphertext/plaintext
//! leaves the repository. SQLite I/O is blocking; keep it off network executors.
use crate::{
    auth::{self, Bytes, Credentials, KeyPair},
    jid,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use wacore_libsignal::engine::{self, Engine, RustCrypto, codec, wire};
use zeroize::Zeroizing;
const MAX_BLOB: usize = 128 * 1024 * 1024;
pub(crate) const MAX_MESSAGE: usize = 16 * 1024 * 1024;
#[derive(Debug)]
pub enum Error {
    Protocol(engine::Error),
    Auth(auth::Error),
    Storage,
    Database {
        operation: &'static str,
        code: Option<i32>,
    },
    InvalidAddress,
    InvalidGroup,
    InvalidMapping,
    MigrationConflict,
    InvalidKey,
    TooLarge,
    LocalIdentityMismatch,
    MissingPreKey,
    MissingSignedPreKey,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signal: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<engine::Error> for Error {
    fn from(e: engine::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Self::Auth(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;
// Keep SQLite operation/code for diagnostics without SQL text, paths or key data.
fn database(operation: &'static str) -> impl FnOnce(rusqlite::Error) -> Error {
    move |error| Error::Database {
        operation,
        code: error.sqlite_extended_error_code(),
    }
}

/// Implementations must atomically apply all changes, roll back on error and
/// serialize concurrent read-modify-write transactions across shared handles.
pub trait Transaction {
    fn get(&self, category: &str, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn get_many(
        &self,
        category: &str,
        ids: &[&str],
    ) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
        let mut result = HashMap::new();
        for id in ids {
            if let Some(value) = self.get(category, id)? {
                result.insert((*id).into(), value);
            }
        }
        Ok(result)
    }
    fn put(&mut self, category: &str, id: &str, value: &[u8]) -> Result<()>;
    fn remove(&mut self, category: &str, id: &str) -> Result<()>;
}
pub trait Store {
    fn transaction<T>(&self, work: impl FnOnce(&mut dyn Transaction) -> Result<T>) -> Result<T>;
}
impl<S: Store> Store for Arc<S> {
    fn transaction<T>(&self, work: impl FnOnce(&mut dyn Transaction) -> Result<T>) -> Result<T> {
        (**self).transaction(work)
    }
}
pub struct SqliteStore {
    connection: Mutex<Connection>,
}
impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStore([redacted])")
    }
}
impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // Create before SQLite opens it so the database never starts world-readable.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Storage),
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Storage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error::Storage)?;
        }
        // macOS /var and other caller-selected parent aliases can be symlinks.
        // Resolve parents after rejecting a symlink database file, then ask
        // SQLite to reject any new symlink redirection on the canonical path.
        let canonical = path.canonicalize().map_err(|_| Error::Storage)?;
        let connection = Connection::open_with_flags(
            canonical,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(database("open"))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(database("busy timeout"))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; CREATE TABLE IF NOT EXISTS rustleys_signal_keys(category TEXT NOT NULL,id TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(category,id)) WITHOUT ROWID;").map_err(database("schema"))?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }
}
struct SqlTransaction<'a, 'b>(&'a rusqlite::Transaction<'b>);
impl Transaction for SqlTransaction<'_, '_> {
    fn get(&self, category: &str, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let length: Option<i64> = self
            .0
            .query_row(
                "SELECT length(value) FROM rustleys_signal_keys WHERE category=?1 AND id=?2",
                params![category, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(database("read length"))?;
        if length.is_none() {
            return Ok(None);
        }
        if length.is_some_and(|n| n < 0 || n as u64 > MAX_BLOB as u64) {
            return Err(Error::TooLarge);
        }
        self.0
            .query_row(
                "SELECT value FROM rustleys_signal_keys WHERE category=?1 AND id=?2",
                params![category, id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|b| b.map(Zeroizing::new))
            .map_err(database("read"))
    }
    fn get_many(
        &self,
        category: &str,
        ids: &[&str],
    ) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
        let mut result = HashMap::new();
        for chunk in ids.chunks(400) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT id,length(value),CASE WHEN length(value)<={MAX_BLOB} THEN value ELSE NULL END FROM rustleys_signal_keys WHERE category=? AND id IN ({placeholders})"
            );
            let mut statement = self
                .0
                .prepare_cached(&sql)
                .map_err(database("batch prepare"))?;
            let rows = statement
                .query_map(
                    rusqlite::params_from_iter(
                        std::iter::once(category).chain(chunk.iter().copied()),
                    ),
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )
                .map_err(database("batch read"))?;
            for row in rows {
                let (id, length, value) = row.map_err(database("batch row"))?;
                if length < 0 || length as u64 > MAX_BLOB as u64 {
                    return Err(Error::TooLarge);
                }
                result.insert(id, Zeroizing::new(value.ok_or(Error::TooLarge)?));
            }
        }
        Ok(result)
    }
    fn put(&mut self, category: &str, id: &str, value: &[u8]) -> Result<()> {
        if value.len() > MAX_BLOB {
            return Err(Error::TooLarge);
        }
        self.0.execute("INSERT INTO rustleys_signal_keys(category,id,value) VALUES(?1,?2,?3) ON CONFLICT(category,id) DO UPDATE SET value=excluded.value",params![category,id,value]).map_err(database("write"))?;
        Ok(())
    }
    fn remove(&mut self, category: &str, id: &str) -> Result<()> {
        self.0
            .execute(
                "DELETE FROM rustleys_signal_keys WHERE category=?1 AND id=?2",
                params![category, id],
            )
            .map_err(database("delete"))?;
        Ok(())
    }
}
impl Store for SqliteStore {
    fn transaction<T>(&self, work: impl FnOnce(&mut dyn Transaction) -> Result<T>) -> Result<T> {
        let mut connection = self.connection.lock().map_err(|_| Error::Storage)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database("begin"))?;
        let output = work(&mut SqlTransaction(&tx))?;
        tx.commit().map_err(database("commit"))?;
        Ok(output)
    }
}
pub(crate) struct OsRandom;
impl engine::RandomSource for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> engine::Result<()> {
        getrandom::getrandom(bytes).map_err(|_| engine::Error::Crypto)
    }
}
fn engine_key(key: &KeyPair) -> Result<engine::KeyPair> {
    key.validate()?;
    Ok(engine::KeyPair {
        public: key
            .public
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
        private: key
            .private
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    })
}
/// Domain-aware address used by Baileys (PN, LID and hosted domains stay distinct).
pub fn protocol_address(jid: &str) -> Result<String> {
    let decoded = jid::jid_decode(jid).map_err(|_| Error::InvalidAddress)?;
    if decoded.user.is_empty()
        || decoded.user.contains('.')
        || (decoded.device == Some(99) && !matches!(decoded.server, "hosted" | "hosted.lid"))
    {
        return Err(Error::InvalidAddress);
    }
    let user = if decoded.domain_type == 0 {
        decoded.user.to_owned()
    } else {
        format!("{}_{}", decoded.user, decoded.domain_type)
    };
    Ok(format!("{user}.{}", decoded.device.unwrap_or(0)))
}
#[derive(Debug, Clone)]
pub struct PublicSignedPreKey {
    pub id: u32,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub identity: [u8; 32],
    pub signed_pre_key: PublicSignedPreKey,
    pub one_time_pre_key: Option<(u32, [u8; 32])>,
}
impl PreKeyBundle {
    pub fn from_credentials(
        creds: &Credentials,
        one_time: Option<(u32, &KeyPair)>,
    ) -> Result<Self> {
        creds.validate()?;
        if let Some((_, pair)) = one_time {
            pair.validate()?;
        }
        Ok(Self {
            registration_id: u32::from(creds.registration_id),
            identity: creds
                .signed_identity_key
                .public
                .expose()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
            signed_pre_key: PublicSignedPreKey {
                id: creds.signed_pre_key.key_id,
                public: creds
                    .signed_pre_key
                    .key_pair
                    .public
                    .expose()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
                signature: creds
                    .signed_pre_key
                    .signature
                    .expose()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?,
            },
            one_time_pre_key: one_time
                .map(|(id, key)| {
                    Ok::<_, Error>((
                        id,
                        key.public
                            .expose()
                            .try_into()
                            .map_err(|_| Error::InvalidKey)?,
                    ))
                })
                .transpose()?,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    PreKey,
    Normal,
}
impl MessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreKey => "pkmsg",
            Self::Normal => "msg",
        }
    }
}
#[derive(Debug)]
pub struct Ciphertext {
    pub kind: MessageType,
    pub bytes: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub base_key: [u8; 33],
    pub registration_id: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionValidation {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}
pub struct Repository<S: Store> {
    pub(crate) store: S,
    identity: engine::KeyPair,
    registration: u32,
    signed: engine::KeyPair,
    signed_id: u32,
}
impl<S: Store> std::fmt::Debug for Repository<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignalRepository([redacted])")
    }
}
impl<S: Store> Repository<S> {
    pub fn new(creds: &Credentials, store: S) -> Result<Self> {
        creds.validate()?;
        let identity = engine_key(&creds.signed_identity_key)?;
        let registration = u32::from(creds.registration_id);
        let mut binding = identity.public.to_vec();
        binding.extend(registration.to_be_bytes());
        store.transaction(|tx| {
            match tx.get("meta", "local-identity")? {
                Some(existing) if existing.as_slice() != binding => {
                    return Err(Error::LocalIdentityMismatch);
                }
                Some(_) => {}
                None => tx.put("meta", "local-identity", &binding)?,
            }
            Ok(())
        })?;
        Ok(Self {
            store,
            identity,
            registration,
            signed: engine_key(&creds.signed_pre_key.key_pair)?,
            signed_id: creds.signed_pre_key.key_id,
        })
    }
    pub fn put_pre_key(&self, id: u32, key: &KeyPair) -> Result<()> {
        let record = engine::PreKeyRecord {
            id,
            key_pair: engine_key(key)?,
        };
        let bytes = Zeroizing::new(codec::encode_pre_key(&record));
        self.store
            .transaction(|tx| tx.put("pre-key", &id.to_string(), &bytes))
    }
    pub fn has_pre_key(&self, id: u32) -> Result<bool> {
        self.store
            .transaction(|tx| Ok(tx.get("pre-key", &id.to_string())?.is_some()))
    }
    pub(crate) fn check_record(&self, record: &engine::SessionRecord) -> Result<()> {
        let check = |state: &engine::SessionState| {
            state.local_identity == self.identity.public
                && state.local_registration == self.registration
        };
        if record.current.as_ref().is_some_and(|state| !check(state)) {
            return Err(Error::LocalIdentityMismatch);
        }
        for archived in &record.previous {
            if !check(&archived.decode()?) {
                return Err(Error::LocalIdentityMismatch);
            }
        }
        Ok(())
    }
    fn load(&self, tx: &mut dyn Transaction, address: &str) -> Result<engine::SessionRecord> {
        let record = tx
            .get("session", address)?
            .map(|bytes| codec::decode_session_record(&RustCrypto, &bytes).map_err(Error::from))
            .transpose()?
            .unwrap_or_default();
        self.check_record(&record)?;
        Ok(record)
    }
    fn save(tx: &mut dyn Transaction, address: &str, record: &engine::SessionRecord) -> Result<()> {
        let bytes = Zeroizing::new(codec::encode_session_record(record));
        tx.put("session", address, &bytes)
    }
    pub fn inject_session(&self, jid: &str, bundle: &PreKeyBundle) -> Result<()> {
        protocol_address(jid)?;
        self.store.transaction(|tx| {
            let address = crate::lid_mapping::resolve_address(tx, jid)?;
            let mut rng = OsRandom;
            let mut engine = Engine::new(&RustCrypto, &mut rng);
            let base_key = engine.generate_key_pair()?;
            let state = engine.initialize_initiator(&engine::InitiatorParameters {
                local_identity: self.identity.clone(),
                local_registration: self.registration,
                remote_identity: bundle.identity,
                remote_registration: bundle.registration_id,
                remote_signed_pre_key: bundle.signed_pre_key.public,
                remote_signed_pre_key_id: bundle.signed_pre_key.id,
                remote_signed_pre_key_signature: bundle.signed_pre_key.signature,
                remote_one_time_pre_key: bundle.one_time_pre_key,
                base_key,
            })?;
            let mut record = self.load(tx, &address)?;
            record.install(state);
            Self::save(tx, &address, &record)?;
            tx.put("identity-key", &address, &bundle.identity)?;
            Ok(())
        })
    }
    pub fn encrypt(&self, jid: &str, plaintext: &[u8]) -> Result<Ciphertext> {
        if plaintext.len() > MAX_MESSAGE - 1024 {
            return Err(Error::TooLarge);
        }
        protocol_address(jid)?;
        self.store.transaction(|tx| {
            let address = crate::lid_mapping::resolve_address(tx, jid)?;
            let mut record = self.load(tx, &address)?;
            let state = record.current.as_ref().ok_or(engine::Error::MissingKey)?;
            let kind = if state.pending_pre_key.is_some() {
                MessageType::PreKey
            } else {
                MessageType::Normal
            };
            // One durable transaction per message is the host's alternative to
            // counter reservations. No ciphertext can leave before commit.
            record.materialize_reservation(&RustCrypto)?;
            record.reservation.waive();
            let bytes = Engine::new(&RustCrypto, &mut OsRandom).encrypt(&mut record, plaintext)?;
            Self::save(tx, &address, &record)?;
            Ok(Ciphertext { kind, bytes })
        })
    }
    pub fn decrypt(&self, jid: &str, kind: MessageType, ciphertext: &[u8]) -> Result<Bytes> {
        if ciphertext.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        protocol_address(jid)?;
        self.store.transaction(|tx| {
            let address = crate::lid_mapping::resolve_address(tx, jid)?;
            let mut record = self.load(tx, &address)?;
            let plaintext = match kind {
                MessageType::Normal => {
                    Engine::new(&RustCrypto, &mut OsRandom).decrypt(&mut record, ciphertext)?
                }
                MessageType::PreKey => {
                    let wrapper = wire::PreKeySignalMessageView::decode(ciphertext)?;
                    let changed = tx
                        .get("identity-key", &address)?
                        .is_some_and(|key| key.as_slice() != wrapper.identity);
                    if changed {
                        record = engine::SessionRecord::default();
                    }
                    let existing = record.current.as_ref().is_some_and(|s| {
                        s.remote_identity == wrapper.identity
                            && s.alice_base_key == Some(wrapper.base_key)
                    }) || record.previous.iter().any(|s| {
                        s.decode().is_ok_and(|s| {
                            s.remote_identity == wrapper.identity
                                && s.alice_base_key == Some(wrapper.base_key)
                        })
                    });
                    if !existing && wrapper.signed_pre_key_id != self.signed_id {
                        return Err(Error::MissingSignedPreKey);
                    }
                    let one_time = if existing {
                        None
                    } else {
                        wrapper
                            .pre_key_id
                            .map(|id| {
                                tx.get("pre-key", &id.to_string())?
                                    .ok_or(Error::MissingPreKey)
                                    .and_then(|bytes| {
                                        codec::decode_pre_key(&bytes)
                                            .map(|record| record.key_pair)
                                            .map_err(Into::into)
                                    })
                            })
                            .transpose()?
                    };
                    let p = engine::ResponderParameters {
                        local_identity: self.identity.clone(),
                        local_registration: self.registration,
                        local_signed_pre_key: self.signed.clone(),
                        local_one_time_pre_key: one_time,
                        remote_identity: wrapper.identity,
                        remote_base_key: wrapper.base_key,
                        remote_registration: wrapper.registration,
                    };
                    let plain = Engine::new(&RustCrypto, &mut OsRandom).decrypt_pre_key(
                        &mut record,
                        ciphertext,
                        &p,
                    )?;
                    if !existing && let Some(id) = wrapper.pre_key_id {
                        tx.remove("pre-key", &id.to_string())?;
                    }
                    tx.put("identity-key", &address, &wrapper.identity)?;
                    plain
                }
            };
            let plaintext = Bytes::new(plaintext);
            Self::save(tx, &address, &record)?;
            Ok(plaintext)
        })
    }
    pub fn session_info(&self, jid: &str) -> Result<Option<SessionInfo>> {
        protocol_address(jid)?;
        self.store.transaction(|tx| {
            let address = crate::lid_mapping::resolve_address(tx, jid)?;
            let record = self.load(tx, &address)?;
            Ok(record.current.as_ref().and_then(|s| {
                s.alice_base_key.map(|base| SessionInfo {
                    base_key: wire::tagged_key(&base),
                    registration_id: s.remote_registration,
                })
            }))
        })
    }
    pub fn validate_session(&self, jid: &str) -> Result<SessionValidation> {
        protocol_address(jid)?;
        self.store.transaction(|tx| {
            let address = crate::lid_mapping::resolve_address(tx, jid)?;
            let Some(bytes) = tx.get("session", &address)? else {
                return Ok(SessionValidation {
                    exists: false,
                    reason: Some("no session"),
                });
            };
            let record = codec::decode_session_record(&RustCrypto, &bytes)?;
            self.check_record(&record)?;
            Ok(if record.current.is_some() {
                SessionValidation {
                    exists: true,
                    reason: None,
                }
            } else {
                SessionValidation {
                    exists: false,
                    reason: Some("no open session"),
                }
            })
        })
    }
    pub fn delete_sessions(&self, jids: &[String]) -> Result<()> {
        for jid in jids {
            protocol_address(jid)?;
        }
        self.store.transaction(|tx| {
            for jid in jids {
                let address = crate::lid_mapping::resolve_address(tx, jid)?;
                tx.remove("session", &address)?;
            }
            Ok(())
        })
    }
}
