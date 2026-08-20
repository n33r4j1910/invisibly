// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Cryptography module — Minimal but functional

use ring::rand::{SecureRandom, SystemRandom};
use ring::hmac;
use std::fs;
use windows::Win32::System::Memory::VirtualLock;
use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows::Win32::Foundation::{LocalFree, HLOCAL};

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const MASTER_KEY_LEN: usize = 32;
// CRYPTPROTECT_UI_FORBIDDEN - never show a UI prompt, this runs headless.
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

// ============================================
// DPAPI - protects the master key at rest so it can't just be read off
// disk like a plain file; only the same Windows account can unprotect it.
// ============================================

fn dpapi_protect(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = CryptProtectData(&mut input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output).is_ok();
        if !ok || output.pbData.is_null() {
            return None;
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Some(result)
    }
}

fn dpapi_unprotect(data: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = CryptUnprotectData(&mut input, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output).is_ok();
        if !ok || output.pbData.is_null() {
            return None;
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData as *mut _));
        Some(result)
    }
}

// ============================================
// MASTER KEY (Base Seed)
// ============================================

// FIX: was silently swallowed - if fs::read() failed (e.g. an ACL lockout
// blocking this account from its own key file), get_master_key() fell straight
// through to generating a throwaway random key with zero diagnostic output.
// That key never matched what any prior run signed, so every baseline/hash
// check failed as "tampered" with no way to tell it apart from real tampering.
static KEY_READ_HEALTHY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn key_read_healthy() -> bool {
    KEY_READ_HEALTHY.load(std::sync::atomic::Ordering::Acquire)
}

pub fn get_master_key() -> [u8; MASTER_KEY_LEN] {
    let key_path = format!("{}\\master_seed.enc", DATA_DIR);

    match fs::read(&key_path) {
        Ok(data) => {
            // Current format: DPAPI-protected.
            if let Some(decrypted) = dpapi_unprotect(&data) {
                if decrypted.len() == MASTER_KEY_LEN {
                    KEY_READ_HEALTHY.store(true, std::sync::atomic::Ordering::Release);
                    let mut key = [0u8; MASTER_KEY_LEN];
                    key.copy_from_slice(&decrypted);
                    return key;
                }
            } else if data.len() == MASTER_KEY_LEN {
                // Legacy format from older installs: raw plaintext key.
                // Use it as-is (so existing self-integrity signatures don't
                // break), then upgrade the on-disk copy to DPAPI-protected.
                KEY_READ_HEALTHY.store(true, std::sync::atomic::Ordering::Release);
                let mut key = [0u8; MASTER_KEY_LEN];
                key.copy_from_slice(&data);
                if let Some(protected) = dpapi_protect(&key) {
                    let _ = fs::write(&key_path, &protected);
                }
                let _ = unsafe { VirtualLock(key.as_ptr() as *mut _, MASTER_KEY_LEN) };
                return key;
            }
            println!("⚠️ master_seed.enc exists but could not be read as a valid key (corrupted?) - generating a temporary key");
            KEY_READ_HEALTHY.store(false, std::sync::atomic::Ordering::Release);
        }
        Err(e) => {
            println!("⚠️ Could not read master_seed.enc ({}) - likely an ACL/permission issue, not real tampering. Generating a temporary key; signatures won't match other runs until access is restored.", e);
            KEY_READ_HEALTHY.store(false, std::sync::atomic::Ordering::Release);
        }
    }

    let rng = SystemRandom::new();
    let mut key = [0u8; MASTER_KEY_LEN];
    rng.fill(&mut key).expect("RNG failed");

    if let Some(protected) = dpapi_protect(&key) {
        let _ = fs::write(&key_path, &protected);
    } else {
        // DPAPI unavailable for some reason - fall back to plaintext rather
        // than losing the key (and breaking every signature check) entirely.
        println!("⚠️ DPAPI protect failed - storing master key unprotected as a fallback");
        let _ = fs::write(&key_path, &key);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_round_trip() {
        let original = b"a 32 byte test master key!!!!!!!";
        assert_eq!(original.len(), MASTER_KEY_LEN);
        let protected = dpapi_protect(original).expect("dpapi_protect should succeed for the current user");
        assert_ne!(protected, original, "protected form should not equal the plaintext");
        let recovered = dpapi_unprotect(&protected).expect("dpapi_unprotect should succeed for the same user");
        assert_eq!(recovered, original, "round-trip should return the exact original bytes");
    }

    #[test]
    fn test_dpapi_unprotect_rejects_garbage() {
        let garbage = b"not a real dpapi blob";
        assert!(dpapi_unprotect(garbage).is_none());
    }
}

