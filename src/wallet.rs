//! Encrypted mnemonic wallet. Notes live here because the chain only stores commitments.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use alloy::{
    primitives::{Address, keccak256},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
    },
};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use coins_bip39::{Entropy, Mnemonic};
use kohaku_minimal_shield::{Note, crypto::P};
use rand::RngExt;
use ruint::aliases::U256 as Ruint;
use serde::{Deserialize, Serialize};

const WALLET_FILE: &str = "wallet.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedNote {
    pub note: Note,
    #[serde(default)]
    pub pending: bool,
    /// `j` in `m/8141'/1'/j'` when the note secrets came from the mnemonic.
    #[serde(default)]
    pub index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secrets {
    pub mnemonic: String,
    pub public_indexes: Vec<u32>,
    pub next_public: u32,
    /// Allocated smart-account indexes. Deployment is checked on chain.
    pub smart_indexes: Vec<u32>,
    /// Next `j` for `m/8141'/1'/j'`. One index per note.
    #[serde(default)]
    pub next_note: u32,
    pub notes: Vec<SavedNote>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub fn data_root(flag: Option<PathBuf>) -> PathBuf {
    flag.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".kohaku-hegota")
    })
}

pub fn list_wallets(root: &Path) -> Result<Vec<String>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.path().join(WALLET_FILE).is_file() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

pub fn wallet_dir(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

/// Indexes discovered while importing a mnemonic. A fresh wallet leaves this unset.
#[derive(Debug, Clone)]
pub struct SeedAccounts {
    pub public_indexes: Vec<u32>,
    pub next_public: u32,
    pub smart_indexes: Vec<u32>,
}

pub fn create_wallet(
    root: &Path,
    name: &str,
    password: &str,
    import: Option<&str>,
    long_seed: bool,
    accounts: Option<SeedAccounts>,
) -> Result<String> {
    let dir = wallet_dir(root, name);
    if dir.join(WALLET_FILE).exists() {
        bail!("wallet {name} already exists");
    }
    let mnemonic = if let Some(phrase) = import {
        let parsed = Mnemonic::<English>::new_from_phrase(phrase.trim())
            .map_err(|e| anyhow::anyhow!("mnemonic: {e}"))?;
        parsed.to_phrase()
    } else {
        let mut rng = rand::rng();
        let mnemonic = if long_seed {
            let mut entropy = [0u8; 32];
            rng.fill(&mut entropy);
            Mnemonic::<English>::new_from_entropy(Entropy::from(entropy))
        } else {
            let mut entropy = [0u8; 16];
            rng.fill(&mut entropy);
            Mnemonic::<English>::new_from_entropy(Entropy::from(entropy))
        };
        mnemonic.to_phrase()
    };
    let accounts = accounts.unwrap_or(SeedAccounts {
        public_indexes: vec![0],
        next_public: 1,
        smart_indexes: Vec::new(),
    });
    let secrets = Secrets {
        mnemonic: mnemonic.clone(),
        public_indexes: accounts.public_indexes,
        next_public: accounts.next_public,
        smart_indexes: accounts.smart_indexes,
        next_note: 0,
        notes: Vec::new(),
    };
    save(root, name, password, &secrets)?;
    Ok(mnemonic)
}

pub fn load(root: &Path, name: &str, password: &str) -> Result<Secrets> {
    let path = wallet_dir(root, name).join(WALLET_FILE);
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let env: Envelope = serde_json::from_str(&raw)?;
    let salt = decode_hex(&env.salt)?;
    let nonce = decode_hex(&env.nonce)?;
    let ct = decode_hex(&env.ciphertext)?;
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| anyhow::anyhow!("wrong password or corrupt wallet"))?;
    Ok(serde_json::from_slice(&plain)?)
}

pub fn save(root: &Path, name: &str, password: &str, secrets: &Secrets) -> Result<()> {
    let dir = wallet_dir(root, name);
    fs::create_dir_all(&dir)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut rng = rand::rng();
    rng.fill(&mut salt);
    rng.fill(&mut nonce);
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = serde_json::to_vec(secrets)?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow::anyhow!("encrypt"))?;
    let env = Envelope {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
    };
    fs::write(dir.join(WALLET_FILE), serde_json::to_vec_pretty(&env)?)?;
    Ok(())
}

pub fn read_password_file(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!("password file must be a regular file");
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 && mode != 0o400 {
        bail!("password file must be mode 0600 or 0400");
    }
    let mut text = fs::read_to_string(path)?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(text)
}

pub fn signer_at(mnemonic: &str, path: &str) -> Result<PrivateKeySigner> {
    MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path(path)?
        .build()
        .map_err(|e| anyhow::anyhow!("derive {path}: {e}"))
}

pub fn eoa_path(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

pub fn smart_owner_path(index: u32) -> String {
    format!("m/44'/60'/0'/8141'/{index}'")
}

/// One hardened index per private note. The key signs a fixed message; it is not the note itself.
pub fn note_path(index: u32) -> String {
    format!("m/8141'/1'/{index}'")
}

const NOTE_MESSAGE: &[u8] = b"kohaku-hegota private note v1";

/// `spend_key` and `rho` from an EIP-191 signature by `m/8141'/1'/j'`.
///
/// The signature is RFC 6979, so the same key always yields the same note secrets.
/// A hardware wallet that can `personal_sign` with that key reproduces them.
pub fn note_at(mnemonic: &str, index: u32, value: Ruint, chain_id: u64, pool: Address) -> Result<Note> {
    let signer = signer_at(mnemonic, &note_path(index))?;
    let sig = signer
        .sign_message_sync(NOTE_MESSAGE)
        .map_err(|e| anyhow::anyhow!("note signature: {e}"))?;
    let bytes = sig.as_bytes();
    Ok(Note {
        spend_key: field_from_sig(&bytes, 0),
        rho: field_from_sig(&bytes, 1),
        value,
        chain_id,
        pool,
    })
}

fn field_from_sig(sig: &[u8; 65], domain: u8) -> Ruint {
    let mut extra = 0u8;
    loop {
        let mut buf = [0u8; 67];
        buf[..65].copy_from_slice(sig);
        buf[65] = domain;
        buf[66] = extra;
        let n = Ruint::from_be_bytes::<32>(keccak256(buf).0) % P;
        if !n.is_zero() {
            return n;
        }
        extra = extra.checked_add(1).expect("field element");
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(key)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).context("hex")
}

#[cfg(test)]
mod tests {
    use super::{create_wallet, eoa_path, load, note_at, note_path, signer_at, smart_owner_path};
    use alloy::primitives::address;
    use kohaku_minimal_shield::crypto::P;
    use ruint::aliases::U256 as Ruint;

    #[test]
    fn round_trip_and_anvil_account_zero() {
        let dir = std::env::temp_dir().join(format!("kohaku-hegota-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let phrase = create_wallet(&dir, "w", "secret", None, false, None).unwrap();
        let loaded = load(&dir, "w", "secret").unwrap();
        assert_eq!(loaded.mnemonic, phrase);
        assert!(load(&dir, "w", "nope").is_err());

        let known = "test test test test test test test test test test test junk";
        let signer = signer_at(known, &eoa_path(0)).unwrap();
        assert_eq!(
            signer.address(),
            address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        );
        let owner = signer_at(known, &smart_owner_path(0)).unwrap();
        assert_ne!(owner.address(), signer.address());
        assert_eq!(
            owner.address(),
            signer_at(known, &smart_owner_path(0)).unwrap().address()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn note_path_signature_is_stable() {
        let phrase = "test test test test test test test test test test test junk";
        assert_eq!(note_path(3), "m/8141'/1'/3'");
        let pool = address!("0xac01c30f28b32dd31d3c2854012e673e74f6b100");
        let one = Ruint::try_from(1u64).unwrap();
        let a = note_at(phrase, 0, one, 8141, pool).unwrap();
        let b = note_at(phrase, 0, one, 8141, pool).unwrap();
        let other = note_at(phrase, 1, one, 8141, pool).unwrap();
        assert_eq!(a.spend_key, b.spend_key);
        assert_eq!(a.rho, b.rho);
        assert_ne!(a.spend_key, a.rho);
        assert_ne!(a.spend_key, other.spend_key);
        assert!(a.spend_key < P && a.rho < P);
    }
}
