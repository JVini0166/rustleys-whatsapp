//! Baileys-compatible primitives backed by RustCrypto and x25519-dalek.
//! Curve signatures (XEdDSA, not ordinary Ed25519) are not implemented here yet.
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher, block_padding::Pkcs7,
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
    InvalidIv,
    InvalidCiphertext,
    Authentication,
    Padding,
    DerivationLength,
    Randomness,
    InvalidPublicKey,
    NonContributoryKey,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn key_iv(key: &[u8], iv: &[u8], iv_len: usize) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::InvalidKey);
    }
    if iv.len() != iv_len {
        return Err(Error::InvalidIv);
    }
    Ok(())
}
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn md5(data: &[u8]) -> [u8; 16] {
    md5::Md5::digest(data).into()
}
pub fn hmac_sha256(data: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
pub fn hmac_sha512(data: &[u8], key: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
pub fn hkdf(input: &[u8], length: usize, salt: Option<&[u8]>, info: &[u8]) -> Result<Vec<u8>> {
    if length > 255 * 32 {
        return Err(Error::DerivationLength);
    }
    let mut out = vec![0; length];
    hkdf::Hkdf::<Sha256>::new(salt, input)
        .expand(info, &mut out)
        .map_err(|_| Error::DerivationLength)?;
    Ok(out)
}
pub fn derive_pairing_code_key(code: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(code.as_bytes(), salt, 131072, &mut out);
    out
}
pub fn aes_encrypt_gcm(data: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    key_iv(key, iv, 12)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::InvalidKey)?
        .encrypt(Nonce::from_slice(iv), Payload { msg: data, aad })
        .map_err(|_| Error::Authentication)
}
pub fn aes_decrypt_gcm(data: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    key_iv(key, iv, 12)?;
    if data.len() < 16 {
        return Err(Error::InvalidCiphertext);
    }
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::InvalidKey)?
        .decrypt(Nonce::from_slice(iv), Payload { msg: data, aad })
        .map_err(|_| Error::Authentication)
}
/// CTR uses the same operation in both directions. It provides no authentication.
pub fn aes_ctr(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    key_iv(key, iv, 16)?;
    let mut out = data.to_vec();
    let mut cipher =
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv).map_err(|_| Error::InvalidKey)?;
    cipher
        .try_apply_keystream(&mut out)
        .map_err(|_| Error::InvalidCiphertext)?;
    Ok(out)
}
pub fn aes_encrypt_with_iv(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    key_iv(key, iv, 16)?;
    Ok(cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| Error::InvalidKey)?
        .encrypt_padded_vec_mut::<Pkcs7>(data))
}
pub fn aes_decrypt_with_iv(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    key_iv(key, iv, 16)?;
    cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|_| Error::InvalidKey)?
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| Error::Padding)
}
/// Like Baileys aesEncrypt: fresh OS-random IV followed by padded CBC ciphertext.
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::InvalidKey);
    }
    let mut iv = [0; 16];
    getrandom::getrandom(&mut iv).map_err(|_| Error::Randomness)?;
    let encrypted = aes_encrypt_with_iv(data, key, &iv)?;
    let mut out = Vec::with_capacity(16 + encrypted.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&encrypted);
    Ok(out)
}
pub fn aes_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Error::InvalidCiphertext);
    }
    aes_decrypt_with_iv(&data[16..], key, &data[..16])
}
pub fn generate_signal_pub_key(public: &[u8]) -> Vec<u8> {
    if public.len() == 33 {
        return public.to_vec();
    }
    let mut out = Vec::with_capacity(public.len() + 1);
    out.push(5);
    out.extend_from_slice(public);
    out
}
/// Private scalar is deliberately excluded from Debug and erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; 32]);
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey([redacted])")
    }
}
impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn generate() -> Result<Self> {
        let mut bytes = [0; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Randomness)?;
        bytes[0] &= 248;
        bytes[31] = (bytes[31] & 127) | 64;
        Ok(Self(bytes))
    }
    /// Explicit export for encrypted/persisted credentials; never log this value.
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.0)).to_bytes()
    }
    pub fn shared_key(&self, public: &[u8]) -> Result<[u8; 32]> {
        let raw = match public.len() {
            32 => public,
            33 if public[0] == 5 => &public[1..],
            _ => return Err(Error::InvalidPublicKey),
        };
        let key = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(raw).map_err(|_| Error::InvalidPublicKey)?,
        );
        let secret = x25519_dalek::StaticSecret::from(self.0).diffie_hellman(&key);
        if !secret.was_contributory() {
            return Err(Error::NonContributoryKey);
        }
        Ok(secret.to_bytes())
    }
}
