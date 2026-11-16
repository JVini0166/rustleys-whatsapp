use rustleys_whatsapp::crypto::*;
use serde_json::Value;
fn bytes(v: &Value) -> Vec<u8> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect()
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/crypto-upstream.json")).unwrap()
}
#[test]
fn symmetric_and_hash_primitives_match_original() {
    let f = fixtures();
    assert_eq!(f["upstream_commit"], rustleys_whatsapp::UPSTREAM_COMMIT);
    for row in f["cases"].as_array().unwrap() {
        let data = bytes(&row["data"]);
        let key = bytes(&row["key"]);
        let iv = bytes(&row["iv"]);
        let nonce = bytes(&row["nonce"]);
        let aad = bytes(&row["aad"]);
        assert_eq!(
            aes_encrypt_with_iv(&data, &key, &iv).unwrap(),
            bytes(&row["cbc"])
        );
        assert_eq!(
            aes_decrypt_with_iv(&bytes(&row["cbc"]), &key, &iv).unwrap(),
            data
        );
        assert_eq!(aes_ctr(&data, &key, &iv).unwrap(), bytes(&row["ctr"]));
        assert_eq!(aes_ctr(&bytes(&row["ctr"]), &key, &iv).unwrap(), data);
        assert_eq!(
            aes_encrypt_gcm(&data, &key, &nonce, &aad).unwrap(),
            bytes(&row["gcm"])
        );
        assert_eq!(
            aes_decrypt_gcm(&bytes(&row["gcm"]), &key, &nonce, &aad).unwrap(),
            data
        );
        assert_eq!(sha256(&data).as_slice(), bytes(&row["sha256"]));
        assert_eq!(md5(&data).as_slice(), bytes(&row["md5"]));
        assert_eq!(hmac_sha256(&data, &key).as_slice(), bytes(&row["hmac256"]));
        assert_eq!(hmac_sha512(&data, &key).as_slice(), bytes(&row["hmac512"]));
    }
}
#[test]
fn derivations_and_curve_agreements_match_original() {
    let f = fixtures();
    for row in f["derivations"].as_array().unwrap() {
        let salt = if row["salt"].is_null() {
            None
        } else {
            Some(bytes(&row["salt"]))
        };
        assert_eq!(
            hkdf(
                &bytes(&row["input"]),
                row["length"].as_u64().unwrap() as usize,
                salt.as_deref(),
                row["info"].as_str().unwrap().as_bytes()
            )
            .unwrap(),
            bytes(&row["result"])
        );
    }
    for row in f["agreements"].as_array().unwrap() {
        let key = PrivateKey::from_bytes(bytes(&row["privateKey"]).try_into().unwrap());
        assert_eq!(
            generate_signal_pub_key(&key.public_key()),
            bytes(&row["publicKey"])
        );
        assert_eq!(
            key.shared_key(&bytes(&row["peerPublic"]))
                .unwrap()
                .as_slice(),
            bytes(&row["shared"])
        );
    }
    let p = &f["pairing"];
    assert_eq!(
        derive_pairing_code_key(p["code"].as_str().unwrap(), &bytes(&p["salt"])).as_slice(),
        bytes(&p["key"])
    );
}
#[test]
fn authentication_failures_and_invalid_inputs_are_errors() {
    let key = [7; 32];
    let nonce = [3; 12];
    let mut encrypted = aes_encrypt_gcm(b"hello", &key, &nonce, b"aad").unwrap();
    assert_eq!(
        aes_decrypt_gcm(&encrypted, &key, &nonce, b"wrong"),
        Err(Error::Authentication)
    );
    encrypted[0] ^= 1;
    assert_eq!(
        aes_decrypt_gcm(&encrypted, &key, &nonce, b"aad"),
        Err(Error::Authentication)
    );
    assert_eq!(
        aes_encrypt_gcm(b"", &[0; 31], &nonce, b""),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        aes_encrypt_gcm(b"", &key, &[0; 11], b""),
        Err(Error::InvalidIv)
    );
    assert_eq!(
        aes_decrypt_gcm(&[0; 15], &key, &nonce, b""),
        Err(Error::InvalidCiphertext)
    );
    let cbc = aes_encrypt_with_iv(b"", &key, &[0; 16]).unwrap();
    let mut bad_iv = [0; 16];
    bad_iv[15] = 1;
    assert_eq!(
        aes_decrypt_with_iv(&cbc, &key, &bad_iv),
        Err(Error::Padding)
    );
    assert_eq!(aes_decrypt(&[0; 15], &key), Err(Error::InvalidCiphertext));
    assert_eq!(hkdf(&[], 8161, None, &[]), Err(Error::DerivationLength));
    let private = PrivateKey::from_bytes([3; 32]);
    assert_eq!(format!("{private:?}"), "PrivateKey([redacted])");
    assert_eq!(private.shared_key(&[0; 32]), Err(Error::NonContributoryKey));
    assert_eq!(private.shared_key(&[0; 31]), Err(Error::InvalidPublicKey));
}
#[test]
fn generated_keys_and_random_iv_ciphertexts_interoperate_internally() {
    let a = PrivateKey::generate().unwrap();
    let b = PrivateKey::generate().unwrap();
    assert_eq!(
        a.shared_key(&b.public_key()).unwrap(),
        b.shared_key(&a.public_key()).unwrap()
    );
    assert_eq!(a.expose_bytes()[0] & 7, 0);
    assert_eq!(a.expose_bytes()[31] & 192, 64);
    let key = [1; 32];
    let first = aes_encrypt(b"message", &key).unwrap();
    let second = aes_encrypt(b"message", &key).unwrap();
    assert_ne!(&first[..16], &second[..16]);
    assert_eq!(aes_decrypt(&first, &key).unwrap(), b"message");
}

#[test]
fn original_signal_signatures_verify_and_corruptions_are_rejected() {
    let f = fixtures();
    let mut legacy_ignored_results = 0;
    for row in f["agreements"].as_array().unwrap() {
        let public = bytes(&row["publicKey"]);
        let message = bytes(&row["message"]);
        let signature = bytes(&row["signature"]);
        assert!(row["nativeVerified"].as_bool().unwrap());
        assert!(verify_signature(&public, &message, &signature));
        assert!(verify_signature(&public[1..], &message, &signature));
        let mut bad = signature.clone();
        bad[0] ^= 128;
        assert!(!row["nativeCorruptedVerified"].as_bool().unwrap());
        assert!(!verify_signature(&public, &message, &bad));
        assert!(!verify_signature(&public, b"wrong message", &signature));
        assert!(!verify_signature(&public, &message, &signature[..63]));
        if row["sdkCorruptedVerified"].as_bool().unwrap() {
            legacy_ignored_results += 1;
        }
    }
    // Keep evidence of the pinned SDK wrapper ignoring a false native result;
    // certificate validation in Rust deliberately checks the actual signature.
    assert_eq!(legacy_ignored_results, 16);
}
#[test]
fn signed_prekeys_bind_the_versioned_public_key() {
    let identity = PrivateKey::from_bytes([11; 32]);
    let pair = signed_key_pair(&identity, 42).unwrap();
    assert_eq!(pair.key_id, 42);
    assert_eq!(pair.private_key.public_key(), pair.public_key);
    assert!(verify_signature(
        &identity.public_key(),
        &generate_signal_pub_key(&pair.public_key),
        &pair.signature
    ));
    assert!(!verify_signature(
        &identity.public_key(),
        &pair.public_key,
        &pair.signature
    ));
    assert!(format!("{pair:?}").contains("[redacted]"));
}
