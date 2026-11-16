//! Baileys credential layout and BufferJSON-compatible byte values.
//! Serialization explicitly exports secrets; do not log or publish serialized credentials.
use crate::crypto;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub enum Error {
    Crypto(crypto::Error),
    Json(serde_json::Error),
    InvalidCredentials(&'static str),
    Unauthenticated,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "credential crypto: {e}"),
            Self::Json(_) => f.write_str("invalid credential JSON"),
            Self::InvalidCredentials(field) => write!(f, "invalid credential field: {field}"),
            Self::Unauthenticated => {
                f.write_str("socket is not authenticated (creds.me.id is missing)")
            }
        }
    }
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}
impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Owned bytes with redacted diagnostics and zeroization on drop. Serialized in
/// Baileys BufferJSON format; arrays and legacy numeric-key objects are accepted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Bytes(Vec<u8>);
impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bytes([redacted])")
    }
}
impl Bytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Buffer {
            r#type: &'static str,
            data: String,
        }
        Buffer {
            r#type: "Buffer",
            data: STANDARD.encode(&self.0),
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        fn numbers<E: serde::de::Error>(
            values: impl IntoIterator<Item = Value>,
        ) -> Result<Vec<u8>, E> {
            values
                .into_iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| E::custom("invalid byte"))
                })
                .collect()
        }
        let bytes = match value {
            Value::Array(values) => numbers::<D::Error>(values)?,
            Value::Object(mut object)
                if object.get("type").and_then(Value::as_str) == Some("Buffer") =>
            {
                match object.remove("data") {
                    Some(Value::String(s)) => STANDARD
                        .decode(s)
                        .map_err(|_| D::Error::custom("invalid base64 bytes"))?,
                    Some(Value::Array(values)) => numbers::<D::Error>(values)?,
                    _ => return Err(D::Error::custom("invalid BufferJSON")),
                }
            }
            Value::Object(object) if !object.is_empty() => {
                let mut entries: Vec<(usize, Value)> = object
                    .into_iter()
                    .map(|(k, v)| {
                        k.parse::<usize>()
                            .map(|n| (n, v))
                            .map_err(|_| D::Error::custom("invalid byte index"))
                    })
                    .collect::<Result<_, _>>()?;
                entries.sort_unstable_by_key(|(n, _)| *n);
                if entries.iter().enumerate().any(|(i, (n, _))| i != *n) {
                    return Err(D::Error::custom("noncontiguous byte indices"));
                }
                numbers::<D::Error>(entries.into_iter().map(|(_, v)| v))?
            }
            _ => return Err(D::Error::custom("invalid byte representation")),
        };
        Ok(Self(bytes))
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public: Bytes,
    pub private: Bytes,
}
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPair([redacted])")
    }
}
impl KeyPair {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_private(&crypto::PrivateKey::generate()?))
    }
    pub fn from_private(key: &crypto::PrivateKey) -> Self {
        Self {
            public: Bytes::new(key.public_key().to_vec()),
            private: Bytes::new(key.expose_bytes().to_vec()),
        }
    }
    pub fn private_key(&self) -> Result<crypto::PrivateKey, Error> {
        let private = self
            .private
            .expose()
            .try_into()
            .map_err(|_| Error::InvalidCredentials("private key length"))?;
        Ok(crypto::PrivateKey::from_bytes(private))
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.private_key()?.public_key().as_slice() != self.public.expose() {
            return Err(Error::InvalidCredentials("public/private key mismatch"));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: Bytes,
    pub key_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_s: Option<u64>,
}
impl std::fmt::Debug for SignedKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedKeyPair([redacted])")
    }
}
// Preserve an explicitly present JSON null for `any`/opaque protocol fields.
// serde Option<Value> otherwise collapses null and absence.
fn present_json<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Ok(Some(Value::deserialize(deserializer)?))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSettings {
    pub unarchive_chats: bool,
    #[serde(
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_disappearing_mode: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
/// Contact/history/account fields retain their original JSON representation,
/// including unknown extensions, until higher protocol layers interpret them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key_pair: KeyPair,
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u16,
    pub adv_secret_key: String,
    pub processed_history_messages: Vec<Value>,
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
    pub account_sync_counter: u32,
    pub account_settings: AccountSettings,
    pub registered: bool,
    #[serde(
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub me: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub account: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub signal_identities: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub my_app_state_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_account_sync_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_prop_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_info: Option<Bytes>,
    #[serde(
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional_data: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.adv_secret_key.zeroize();
        self.pairing_code.zeroize();
    }
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([redacted])")
    }
}
impl Credentials {
    pub fn generate() -> Result<Self, Error> {
        let identity = crypto::PrivateKey::generate()?;
        let signed = crypto::signed_key_pair(&identity, 1)?;
        let mut secret = zeroize::Zeroizing::new([0; 32]);
        getrandom::getrandom(secret.as_mut()).map_err(|_| crypto::Error::Randomness)?;
        let mut registration = [0; 2];
        getrandom::getrandom(&mut registration).map_err(|_| crypto::Error::Randomness)?;
        Ok(Self {
            noise_key: KeyPair::generate()?,
            pairing_ephemeral_key_pair: KeyPair::generate()?,
            signed_identity_key: KeyPair::from_private(&identity),
            signed_pre_key: SignedKeyPair {
                key_pair: KeyPair::from_private(&signed.private_key),
                signature: Bytes::new(signed.signature.to_vec()),
                key_id: 1,
                timestamp_s: None,
            },
            registration_id: registration_id_from_random(registration),
            adv_secret_key: STANDARD.encode(secret.as_ref()),
            processed_history_messages: Vec::new(),
            next_pre_key_id: 1,
            first_unuploaded_pre_key_id: 1,
            account_sync_counter: 0,
            account_settings: AccountSettings {
                unarchive_chats: false,
                default_disappearing_mode: None,
                extra: BTreeMap::new(),
            },
            registered: false,
            me: None,
            account: None,
            signal_identities: None,
            my_app_state_key_id: None,
            last_account_sync_timestamp: None,
            platform: None,
            pairing_code: None,
            last_prop_hash: None,
            routing_info: None,
            additional_data: None,
            extra: BTreeMap::new(),
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        const RESERVED: &[&str] = &[
            "noiseKey",
            "pairingEphemeralKeyPair",
            "signedIdentityKey",
            "signedPreKey",
            "registrationId",
            "advSecretKey",
            "processedHistoryMessages",
            "nextPreKeyId",
            "firstUnuploadedPreKeyId",
            "accountSyncCounter",
            "accountSettings",
            "registered",
            "me",
            "account",
            "signalIdentities",
            "myAppStateKeyId",
            "lastAccountSyncTimestamp",
            "platform",
            "pairingCode",
            "lastPropHash",
            "routingInfo",
            "additionalData",
        ];
        if self.extra.keys().any(|k| RESERVED.contains(&k.as_str()))
            || self
                .account_settings
                .extra
                .keys()
                .any(|k| matches!(k.as_str(), "unarchiveChats" | "defaultDisappearingMode"))
        {
            return Err(Error::InvalidCredentials("reserved extension field"));
        }
        self.noise_key.validate()?;
        self.pairing_ephemeral_key_pair.validate()?;
        self.signed_identity_key.validate()?;
        self.signed_pre_key.key_pair.validate()?;
        if self.registration_id > 16383 {
            return Err(Error::InvalidCredentials("registrationId"));
        }
        let secret = zeroize::Zeroizing::new(
            STANDARD
                .decode(&self.adv_secret_key)
                .map_err(|_| Error::InvalidCredentials("advSecretKey"))?,
        );
        if secret.len() != 32 {
            return Err(Error::InvalidCredentials("advSecretKey length"));
        }
        if !crypto::verify_signature(
            self.signed_identity_key.public.expose(),
            &crypto::generate_signal_pub_key(self.signed_pre_key.key_pair.public.expose()),
            self.signed_pre_key.signature.expose(),
        ) {
            return Err(Error::InvalidCredentials("signed prekey signature"));
        }
        Ok(())
    }
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        let creds: Self = serde_json::from_slice(json)?;
        creds.validate()?;
        Ok(creds)
    }
    pub fn to_json(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        Ok(zeroize::Zeroizing::new(serde_json::to_vec(self)?))
    }
    pub fn assert_me_id(&self) -> Result<&str, Error> {
        self.me
            .as_ref()
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(Error::Unauthenticated)
    }
}
/// Exact pinned Baileys behavior: Uint16Array.from(randomBytes(2))[0] keeps
/// the first byte rather than interpreting the two bytes as a u16.
pub fn registration_id_from_random(bytes: [u8; 2]) -> u16 {
    u16::from(bytes[0]) & 16383
}
