//! Synchronous local Baileys multi-file persistence. Run blocking I/O off the
//! network executor. Each file replacement is atomic; a multi-key batch is not
//! a database transaction. A per-directory advisory lock serializes Rust users.
use crate::auth::{self, Credentials};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;
const DEFAULT_MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Debug)]
pub enum Error {
    Io(io::ErrorKind),
    Auth(auth::Error),
    InvalidJson,
    InvalidPath,
    FileTooLarge,
    LockPoisoned,
    Conflict,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(e) => write!(f, "{e}"),
            _ => write!(f, "auth storage: {self:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Self::Auth(e)
    }
}
/// All categories in the pinned Baileys SignalDataTypeMap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    PreKey,
    Session,
    SenderKey,
    SenderKeyMemory,
    AppStateSyncKey,
    AppStateSyncVersion,
    LidMapping,
    DeviceList,
    TcToken,
    IdentityKey,
}
impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreKey => "pre-key",
            Self::Session => "session",
            Self::SenderKey => "sender-key",
            Self::SenderKeyMemory => "sender-key-memory",
            Self::AppStateSyncKey => "app-state-sync-key",
            Self::AppStateSyncVersion => "app-state-sync-version",
            Self::LidMapping => "lid-mapping",
            Self::DeviceList => "device-list",
            Self::TcToken => "tctoken",
            Self::IdentityKey => "identity-key",
        }
    }
}
pub type KeySet = BTreeMap<Category, BTreeMap<String, Option<Value>>>;
struct Lock<'a>(MutexGuard<'a, File>);
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
/// Filenames match useMultiFileAuthState: '/' becomes '__', ':' becomes '-'.
/// As upstream, distinct IDs can normalize to the same name. Avoid IDs with
/// ambiguous normalization. Backslashes/control characters are rejected.
pub struct MultiFileStore {
    directory: PathBuf,
    lock: Mutex<File>,
    max_file_bytes: usize,
}
impl std::fmt::Debug for MultiFileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MultiFileStore([redacted])")
    }
}
impl MultiFileStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::with_limit(path, DEFAULT_MAX_FILE_BYTES)
    }
    pub fn with_limit(path: impl AsRef<Path>, max_file_bytes: usize) -> Result<Self, Error> {
        let path = path.as_ref();
        if max_file_bytes == 0 || max_file_bytes > isize::MAX as usize {
            return Err(Error::FileTooLarge);
        }
        match fs::symlink_metadata(path) {
            Ok(info) if info.file_type().is_symlink() || !info.is_dir() => {
                return Err(Error::InvalidPath);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(path)?;
            }
            Err(e) => return Err(e.into()),
        }
        let directory = path.canonicalize()?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options.open(directory.join(".rustleys.lock"))?;
        Ok(Self {
            directory,
            lock: Mutex::new(lock),
            max_file_bytes,
        })
    }
    fn acquire(&self) -> Result<Lock<'_>, Error> {
        let file = self.lock.lock().map_err(|_| Error::LockPoisoned)?;
        file.lock()?;
        Ok(Lock(file))
    }
    fn filename(category: Category, id: &str) -> Result<String, Error> {
        if id.contains('\\') || id.chars().any(char::is_control) {
            return Err(Error::InvalidPath);
        }
        Ok(format!(
            "{}-{}.json",
            category.as_str(),
            id.replace('/', "__").replace(':', "-")
        ))
    }
    fn read(&self, filename: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let path = self.directory.join(filename);
        // O_NOFOLLOW closes the metadata/read race on Unix; explicit metadata
        // rejection also protects other platforms for ordinary local use.
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => return Err(Error::InvalidPath),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if file.metadata()?.len() > self.max_file_bytes as u64 {
            return Err(Error::FileTooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(self.max_file_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.max_file_bytes {
            return Err(Error::FileTooLarge);
        }
        Ok(Some(bytes))
    }
    fn write(&self, filename: &str, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.max_file_bytes {
            return Err(Error::FileTooLarge);
        }
        let target = self.directory.join(filename);
        if let Ok(m) = fs::symlink_metadata(&target)
            && (m.file_type().is_symlink() || !m.is_file())
        {
            return Err(Error::InvalidPath);
        }
        let mut temp = NamedTempFile::new_in(&self.directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(target).map_err(|e| Error::from(e.error))?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    /// Unlike the upstream helper, corruption/permission errors are returned;
    /// only an absent creds.json permits initialization of fresh credentials.
    pub fn load_credentials(&self) -> Result<Option<Credentials>, Error> {
        let _lock = self.acquire()?;
        self.read("creds.json")?
            .map(|json| Credentials::from_json(&json).map_err(Into::into))
            .transpose()
    }
    pub fn load_or_initialize(&self) -> Result<Credentials, Error> {
        match self.load_credentials()? {
            Some(creds) => Ok(creds),
            None => Ok(Credentials::generate()?),
        }
    }
    pub fn save_credentials(&self, creds: &Credentials) -> Result<(), Error> {
        let bytes = creds.to_json()?;
        let _lock = self.acquire()?;
        self.write("creds.json", &bytes)
    }
    /// Compare and replace under the same directory lock. The caller must
    /// already have persisted the original account before linking a device.
    pub fn compare_and_save_credentials(
        &self,
        expected: &Credentials,
        updated: &Credentials,
    ) -> Result<(), Error> {
        let expected = expected.to_json()?;
        let updated = updated.to_json()?;
        let _lock = self.acquire()?;
        let current = self.read("creds.json")?.ok_or(Error::Conflict)?;
        let current = Credentials::from_json(&current)?.to_json()?;
        use subtle::ConstantTimeEq;
        if !bool::from(crate::crypto::sha256(&current).ct_eq(&crate::crypto::sha256(&expected))) {
            return Err(Error::Conflict);
        }
        self.write("creds.json", &updated)
    }
    /// Missing IDs are null, matching the upstream multi-file adapter. Values
    /// preserve BufferJSON/protobuf objects; typed protocol conversion is done
    /// by the caller (the JS adapter creates AppStateSyncKeyData instances).
    pub fn get(
        &self,
        category: Category,
        ids: &[String],
    ) -> Result<BTreeMap<String, Option<Value>>, Error> {
        let filenames: Vec<_> = ids
            .iter()
            .map(|id| Self::filename(category, id))
            .collect::<Result<_, _>>()?;
        let _lock = self.acquire()?;
        let mut result = BTreeMap::new();
        for (id, filename) in ids.iter().zip(filenames) {
            let value = self
                .read(&filename)?
                .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| Error::InvalidJson))
                .transpose()?;
            result.insert(id.clone(), value);
        }
        Ok(result)
    }
    pub fn set(&self, data: &KeySet) -> Result<(), Error> {
        // Validate/serialize the complete batch before the first write.
        let mut writes = Vec::new();
        for (category, values) in data {
            for (id, value) in values {
                let filename = Self::filename(*category, id)?;
                let bytes = match value {
                    None => None,
                    Some(value)
                        if value.is_null()
                            || value == &Value::Bool(false)
                            || value.as_f64() == Some(0.0)
                            || value.as_str() == Some("") =>
                    {
                        None
                    }
                    Some(value) => Some(Zeroizing::new(
                        serde_json::to_vec(value).map_err(|_| Error::InvalidJson)?,
                    )),
                };
                if bytes
                    .as_ref()
                    .is_some_and(|b| b.len() > self.max_file_bytes)
                {
                    return Err(Error::FileTooLarge);
                }
                writes.push((filename, bytes));
            }
        }
        let _lock = self.acquire()?;
        for (filename, bytes) in writes {
            match bytes {
                Some(bytes) => self.write(&filename, &bytes)?,
                None => match fs::remove_file(self.directory.join(filename)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                },
            }
        }
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
