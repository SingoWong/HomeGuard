//! AEAD cipher implementation for Shadowsocks
//!
//! Supports:
//! - AES-128-GCM
//! - AES-256-GCM
//! - ChaCha20-Poly1305 (IETF variant)

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, AES_128_GCM, AES_256_GCM};
use ring::hkdf::{self, Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{Error, ErrorKind, Result};

/// Shadowsocks HKDF info string
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";

/// Supported cipher methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl CipherMethod {
    /// Parse cipher method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" => Some(CipherMethod::Aes128Gcm),
            "aes-256-gcm" => Some(CipherMethod::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => {
                Some(CipherMethod::ChaCha20IetfPoly1305)
            }
            _ => None,
        }
    }

    /// Get the key size in bytes
    pub fn key_size(&self) -> usize {
        match self {
            CipherMethod::Aes128Gcm => 16,
            CipherMethod::Aes256Gcm => 32,
            CipherMethod::ChaCha20IetfPoly1305 => 32,
        }
    }

    /// Get the salt size in bytes (same as key size for SS)
    pub fn salt_size(&self) -> usize {
        self.key_size()
    }

    /// Get the nonce size in bytes (always 12 for AEAD)
    pub fn nonce_size(&self) -> usize {
        12
    }

    /// Get the authentication tag size in bytes (always 16 for AEAD)
    pub fn tag_size(&self) -> usize {
        16
    }

    /// Get the ring algorithm
    fn algorithm(&self) -> &'static aead::Algorithm {
        match self {
            CipherMethod::Aes128Gcm => &AES_128_GCM,
            CipherMethod::Aes256Gcm => &AES_256_GCM,
            CipherMethod::ChaCha20IetfPoly1305 => &CHACHA20_POLY1305,
        }
    }
}

/// AEAD cipher for Shadowsocks
///
/// Holds the master key and can create encryptor/decryptor sessions.
#[derive(Clone)]
pub struct AeadCipher {
    method: CipherMethod,
    master_key: Vec<u8>,
}

impl AeadCipher {
    /// Create a new AEAD cipher from password
    pub fn new(method: CipherMethod, password: &str) -> Self {
        let key_size = method.key_size();
        let master_key = evp_bytes_to_key(password.as_bytes(), key_size);

        Self { method, master_key }
    }

    /// Get the cipher method
    pub fn method(&self) -> CipherMethod {
        self.method
    }

    /// Generate a random salt
    pub fn generate_salt(&self) -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut salt = vec![0u8; self.method.salt_size()];
        rng.fill(&mut salt).expect("Failed to generate random salt");
        salt
    }

    /// Create an encryptor with the given salt
    pub fn encryptor(&self, salt: &[u8]) -> AeadEncryptor {
        let subkey = self.derive_subkey(salt);
        let unbound_key = UnboundKey::new(self.method.algorithm(), &subkey)
            .expect("Failed to create unbound key");
        let key = LessSafeKey::new(unbound_key);

        AeadEncryptor {
            key,
            nonce_counter: 0,
            tag_size: self.method.tag_size(),
        }
    }

    /// Create a decryptor with the given salt
    pub fn decryptor(&self, salt: &[u8]) -> AeadDecryptor {
        let subkey = self.derive_subkey(salt);
        let unbound_key = UnboundKey::new(self.method.algorithm(), &subkey)
            .expect("Failed to create unbound key");
        let key = LessSafeKey::new(unbound_key);

        AeadDecryptor {
            key,
            nonce_counter: 0,
            tag_size: self.method.tag_size(),
        }
    }

    /// Derive subkey from master key and salt using HKDF-SHA1
    fn derive_subkey(&self, salt: &[u8]) -> Vec<u8> {
        let salt = Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let prk = salt.extract(&self.master_key);

        let mut subkey = vec![0u8; self.method.key_size()];
        let okm = prk
            .expand(&[SS_SUBKEY_INFO], HkdfLen(self.method.key_size()))
            .expect("HKDF expand failed");
        okm.fill(&mut subkey).expect("HKDF fill failed");

        subkey
    }
}

/// Helper struct for HKDF output length
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// AEAD Encryptor session
///
/// Maintains a nonce counter that increments after each encryption.
pub struct AeadEncryptor {
    key: LessSafeKey,
    nonce_counter: u64,
    tag_size: usize,
}

impl AeadEncryptor {
    /// Encrypt data in place, appending the authentication tag
    ///
    /// Returns the ciphertext + tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();

        // Allocate buffer for ciphertext + tag
        let mut ciphertext = plaintext.to_vec();
        ciphertext.resize(plaintext.len() + self.tag_size, 0);

        self.key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut ciphertext[..plaintext.len()])
            .map(|tag| {
                ciphertext[plaintext.len()..].copy_from_slice(tag.as_ref());
            })
            .expect("Encryption failed");

        ciphertext
    }

    /// Encrypt payload in Shadowsocks format: [length][tag][payload][tag]
    ///
    /// Length is 2 bytes big-endian, encrypted with its own tag.
    pub fn encrypt_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        // Encrypt length (2 bytes)
        let length = (payload.len() as u16).to_be_bytes();
        let encrypted_length = self.encrypt(&length);

        // Encrypt payload
        let encrypted_payload = self.encrypt(payload);

        // Combine: [encrypted_length][encrypted_payload]
        let mut result = Vec::with_capacity(encrypted_length.len() + encrypted_payload.len());
        result.extend_from_slice(&encrypted_length);
        result.extend_from_slice(&encrypted_payload);

        result
    }

    /// Get the next nonce (little-endian counter in first 8 bytes, rest zeros)
    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter += 1;
        Nonce::assume_unique_for_key(nonce_bytes)
    }
}

/// AEAD Decryptor session
///
/// Maintains a nonce counter that increments after each decryption.
pub struct AeadDecryptor {
    key: LessSafeKey,
    nonce_counter: u64,
    tag_size: usize,
}

impl AeadDecryptor {
    /// Decrypt ciphertext (including authentication tag)
    ///
    /// Returns the plaintext if authentication succeeds.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < self.tag_size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Ciphertext too short",
            ));
        }

        let nonce = self.next_nonce();

        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Decryption failed"))?;

        Ok(plaintext.to_vec())
    }

    /// Get the next nonce
    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter += 1;
        Nonce::assume_unique_for_key(nonce_bytes)
    }
}

/// OpenSSL EVP_BytesToKey compatible key derivation
///
/// This is used for compatibility with existing Shadowsocks implementations.
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};

    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();

    while key.len() < key_len {
        let mut hasher = Md5::new();
        if !prev.is_empty() {
            hasher.update(&prev);
        }
        hasher.update(password);
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }

    key.truncate(key_len);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_method_from_str() {
        assert_eq!(
            CipherMethod::from_str("aes-128-gcm"),
            Some(CipherMethod::Aes128Gcm)
        );
        assert_eq!(
            CipherMethod::from_str("AES-256-GCM"),
            Some(CipherMethod::Aes256Gcm)
        );
        assert_eq!(
            CipherMethod::from_str("chacha20-ietf-poly1305"),
            Some(CipherMethod::ChaCha20IetfPoly1305)
        );
        assert_eq!(
            CipherMethod::from_str("chacha20-poly1305"),
            Some(CipherMethod::ChaCha20IetfPoly1305)
        );
        assert_eq!(CipherMethod::from_str("unknown"), None);
    }

    #[test]
    fn test_cipher_method_sizes() {
        assert_eq!(CipherMethod::Aes128Gcm.key_size(), 16);
        assert_eq!(CipherMethod::Aes256Gcm.key_size(), 32);
        assert_eq!(CipherMethod::ChaCha20IetfPoly1305.key_size(), 32);

        // All AEAD ciphers have 12-byte nonce and 16-byte tag
        for method in [
            CipherMethod::Aes128Gcm,
            CipherMethod::Aes256Gcm,
            CipherMethod::ChaCha20IetfPoly1305,
        ] {
            assert_eq!(method.nonce_size(), 12);
            assert_eq!(method.tag_size(), 16);
        }
    }

    #[test]
    fn test_evp_bytes_to_key() {
        // Test vector: password "test", key_len 16
        let key = evp_bytes_to_key(b"test", 16);
        assert_eq!(key.len(), 16);

        // Same password should produce same key
        let key2 = evp_bytes_to_key(b"test", 16);
        assert_eq!(key, key2);

        // Different password should produce different key
        let key3 = evp_bytes_to_key(b"different", 16);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_evp_bytes_to_key_32() {
        let key = evp_bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let cipher = AeadCipher::new(CipherMethod::ChaCha20IetfPoly1305, "test_password");
        let salt = cipher.generate_salt();

        let mut encryptor = cipher.encryptor(&salt);
        let mut decryptor = cipher.decryptor(&salt);

        let plaintext = b"Hello, Shadowsocks!";
        let ciphertext = encryptor.encrypt(plaintext);

        // Ciphertext should be plaintext + tag
        assert_eq!(ciphertext.len(), plaintext.len() + cipher.method.tag_size());

        let decrypted = decryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_multiple_encryptions() {
        let cipher = AeadCipher::new(CipherMethod::Aes256Gcm, "test");
        let salt = cipher.generate_salt();

        let mut encryptor = cipher.encryptor(&salt);
        let mut decryptor = cipher.decryptor(&salt);

        // Encrypt multiple messages
        let messages = [b"First message".as_slice(), b"Second message", b"Third"];

        let ciphertexts: Vec<_> = messages.iter().map(|m| encryptor.encrypt(m)).collect();

        // Decrypt in same order
        for (i, ct) in ciphertexts.iter().enumerate() {
            let pt = decryptor.decrypt(ct).unwrap();
            assert_eq!(pt, messages[i]);
        }
    }

    #[test]
    fn test_aead_wrong_order_fails() {
        let cipher = AeadCipher::new(CipherMethod::Aes128Gcm, "test");
        let salt = cipher.generate_salt();

        let mut encryptor = cipher.encryptor(&salt);
        let mut decryptor = cipher.decryptor(&salt);

        let ct1 = encryptor.encrypt(b"First");
        let ct2 = encryptor.encrypt(b"Second");

        // Decrypt second message first (wrong nonce) should fail
        assert!(decryptor.decrypt(&ct2).is_err());

        // Now first message won't decrypt either (nonce already incremented)
        assert!(decryptor.decrypt(&ct1).is_err());
    }

    #[test]
    fn test_different_salts_produce_different_subkeys() {
        let cipher = AeadCipher::new(CipherMethod::ChaCha20IetfPoly1305, "test");

        let salt1 = cipher.generate_salt();
        let salt2 = cipher.generate_salt();

        let mut enc1 = cipher.encryptor(&salt1);
        let mut enc2 = cipher.encryptor(&salt2);

        let plaintext = b"test data";
        let ct1 = enc1.encrypt(plaintext);
        let ct2 = enc2.encrypt(plaintext);

        // Same plaintext with different salts should produce different ciphertexts
        // (different subkeys derived from different salts)
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_generate_salt_randomness() {
        let cipher = AeadCipher::new(CipherMethod::Aes256Gcm, "test");

        let salt1 = cipher.generate_salt();
        let salt2 = cipher.generate_salt();

        // Salts should be different (extremely unlikely to be equal)
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), cipher.method.salt_size());
    }

    #[test]
    fn test_encrypt_payload_format() {
        let cipher = AeadCipher::new(CipherMethod::ChaCha20IetfPoly1305, "test");
        let salt = cipher.generate_salt();
        let mut encryptor = cipher.encryptor(&salt);

        let payload = b"Hello";
        let encrypted = encryptor.encrypt_payload(payload);

        // Should contain: encrypted_length (2 + 16) + encrypted_payload (5 + 16)
        let expected_len = (2 + 16) + (5 + 16);
        assert_eq!(encrypted.len(), expected_len);
    }
}
