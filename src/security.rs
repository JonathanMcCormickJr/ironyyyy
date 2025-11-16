use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Result, anyhow};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;

/// Serialized form of the encrypted payload stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce: String,
    pub payload: String,
}

#[cfg(test)]
const ARGON2_MEMORY_COST: u32 = 1024; // smaller for faster tests
#[cfg(not(test))]
const ARGON2_MEMORY_COST: u32 = 65_536; // larger for enhanced security

#[cfg(test)]
const ARGON2_TIME_COST: u32 = 1; // smaller for faster tests
#[cfg(not(test))]
const ARGON2_TIME_COST: u32 = 8; // larger for enhanced security

fn argon2_params() -> Result<Params, argon2::Error> {
    Ok(Params::new(
        ARGON2_MEMORY_COST, // memory cost in KiB
        ARGON2_TIME_COST,   // time cost
        1,                  // parallelism
        None,               // output length (default is 32 bytes)
    )?)
}

fn argon2_instance() -> Result<Argon2<'static>, argon2::Error> {
    let params = argon2_params()?;
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}

/// Creates a `SaltString` from a UUID so that we can derive deterministic salts per user.
pub fn salt_from_uuid(uuid: &Uuid) -> Result<SaltString> {
    SaltString::encode_b64(uuid.as_bytes()).map_err(|e| anyhow!("salt encoding: {e}"))
}

/// Hashes a password using Argon2id and the provided salt for later verification.
pub fn hash_password(password: &str, salt: &SaltString) -> Result<String> {
    let argon2 = argon2_instance().map_err(|e| anyhow!("argon2 init: {e}"))?;
    let hash = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| anyhow!("hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Derives an encryption key given the raw password and the salt bytes (UUID).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
    let argon2 = argon2_instance().map_err(|e| anyhow!("argon2 init: {e}"))?;
    let mut key = [0u8; AES_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("derive key: {e}"))?;
    Ok(key)
}

/// Verifies that the provided password matches the stored hash inside the payload.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<()> {
    let parsed = PasswordHash::new(stored_hash).map_err(|e| anyhow!("hash parse: {e}"))?;
    let argon2 = argon2_instance().map_err(|e| anyhow!("argon2 init: {e}"))?;
    argon2
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|e| anyhow!("password verification: {e}"))
}

fn build_cipher(key: &[u8; AES_KEY_LEN]) -> Aes256Gcm {
    let key = Key::<Aes256Gcm>::from_slice(key);
    Aes256Gcm::new(key)
}

/// Encrypts an arbitrary payload using AES-256-GCM.
pub fn encrypt_payload(payload: &[u8], key: &[u8; AES_KEY_LEN]) -> Result<EncryptedBlob> {
    let cipher = build_cipher(key);
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    Ok(EncryptedBlob {
        nonce: STANDARD.encode(nonce_bytes),
        payload: STANDARD.encode(ciphertext),
    })
}

/// Decrypts an `EncryptedBlob` and returns the plaintext bytes.
pub fn decrypt_payload(blob: &EncryptedBlob, key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = build_cipher(key);
    let nonce_bytes = STANDARD
        .decode(&blob.nonce)
        .map_err(|e| anyhow!("invalid nonce: {e}"))?;
    let ciphertext = STANDARD
        .decode(&blob.payload)
        .map_err(|e| anyhow!("invalid ciphertext: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let password = "s3cure";
        let uuid = Uuid::new_v4();
        let salt = salt_from_uuid(&uuid).expect("salt generation");
        let key = derive_key(password, uuid.as_bytes()).expect("key derivation");
        let hash = hash_password(password, &salt).expect("hashing");
        verify_password(password, &hash).expect("verification");

        let payload = b"whisper secrets";
        let blob = encrypt_payload(payload, &key).expect("encryption");
        let decrypted = decrypt_payload(&blob, &key).expect("decryption");
        assert_eq!(payload, decrypted.as_slice());
    }
}
