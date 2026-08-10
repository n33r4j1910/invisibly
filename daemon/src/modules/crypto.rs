// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Cryptography module — Minimal but functional

use ring::rand::{SecureRandom, SystemRandom};
use ring::hmac;
use std::fs;
use windows::Win32::System::Memory::VirtualLock;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const MASTER_KEY_LEN: usize = 32;

// ============================================
// MASTER KEY (Base Seed)
// ============================================

pub fn get_master_key() -> [u8; MASTER_KEY_LEN] {
    let key_path = format!("{}\\master_seed.enc", DATA_DIR); 

    if let Ok(data) = fs::read(&key_path) {
        if data.len() == MASTER_KEY_LEN {
            let mut key = [0u8; MASTER_KEY_LEN];
            key.copy_from_slice(&data);
            return key;
        }
    }

    let rng = SystemRandom::new();
    let mut key = [0u8; MASTER_KEY_LEN];
    rng.fill(&mut key).expect("RNG failed");

    let _ = fs::write(&key_path, &key);
    let _ = unsafe { VirtualLock(key.as_ptr() as *mut _, MASTER_KEY_LEN) };

    key
}

// ============================================
// KEY DERIVATION
// ============================================

pub fn get_hmac_key() -> [u8; MASTER_KEY_LEN] {
    let base = get_master_key();
    use ring::digest::{digest, SHA256};
    let mut result = [0u8; MASTER_KEY_LEN];
    let data = [base.as_ref(), b"hmac-key"].concat();
    let hash = digest(&SHA256, &data);
    result.copy_from_slice(hash.as_ref());
    result
}

pub fn get_xor_key() -> [u8; MASTER_KEY_LEN] {
    let base = get_master_key();
    use ring::digest::{digest, SHA256};
    let mut result = [0u8; MASTER_KEY_LEN];
    let data = [base.as_ref(), b"xor-key"].concat();
    let hash = digest(&SHA256, &data);
    result.copy_from_slice(hash.as_ref());
    result
}

// ============================================
// HMAC SIGNING
// ============================================

pub fn hmac_sign(data: &[u8]) -> String {
    let key_bytes = get_hmac_key();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let tag = hmac::sign(&key, data);
    hex::encode(tag.as_ref())
}

pub fn hmac_verify(data: &[u8], signature: &str) -> bool {
    let key_bytes = get_hmac_key();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let expected = hex::decode(signature).unwrap_or_default();
    hmac::verify(&key, data, &expected).is_ok()
}

// ============================================
// ENCRYPT / DECRYPT (XOR-based obfuscation)
// ============================================

pub fn encrypt_data(data: &[u8], key: &[u8; MASTER_KEY_LEN]) -> Vec<u8> {
    let mut result = data.to_vec();
    for i in 0..result.len() {
        result[i] ^= key[i % key.len()];
    }
    result
}

pub fn decrypt_data(encrypted: &[u8], key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String> {
    let mut result = encrypted.to_vec();
    for i in 0..result.len() {
        result[i] ^= key[i % key.len()];
    }
    Ok(result)
}

pub fn encrypt_baseline(data: &str) -> Vec<u8> {
    let key = get_xor_key();
    encrypt_data(data.as_bytes(), &key)
}

pub fn decrypt_baseline(encrypted: &[u8]) -> Result<String, String> {
    let key = get_xor_key();
    let decrypted = decrypt_data(encrypted, &key)?;
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8".to_string())
}

pub fn encrypt_consent(data: &str) -> Vec<u8> {
    let key = get_xor_key();
    encrypt_data(data.as_bytes(), &key)
}

pub fn decrypt_consent(encrypted: &[u8]) -> Result<String, String> {
    let key = get_xor_key();
    let decrypted = decrypt_data(encrypted, &key)?;
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8".to_string())
}

pub fn encrypt_event(data: &str) -> Vec<u8> {
    let key = get_xor_key();
    encrypt_data(data.as_bytes(), &key)
}

pub fn decrypt_event(encrypted: &[u8]) -> Result<String, String> {
    let key = get_xor_key();
    let decrypted = decrypt_data(encrypted, &key)?;
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8".to_string())
}