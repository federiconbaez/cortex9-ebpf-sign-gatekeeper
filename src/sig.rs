//! Stub signature format (NOT Sigstore/cosign): ed25519 over a domain-separated
//! digest of the exact object bytes and the exact manifest bytes.
//!
//! message = b"EBPF-SIGN-GATEKEEPER-V1\0" || sha256(object) || sha256(manifest)

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const FORMAT: &str = "ebpf-sign-gatekeeper/stub-ed25519/v1";
const DOMAIN: &[u8] = b"EBPF-SIGN-GATEKEEPER-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigFile {
    pub format: String,
    pub key_id: String,
    pub object_sha256: String,
    pub manifest_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigError {
    Missing,
    Malformed(String),
    UnknownKey(String),
    ObjectHashMismatch,
    ManifestHashMismatch,
    BadSignature,
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn key_id(vk: &VerifyingKey) -> String {
    hex::encode(&sha256(vk.as_bytes())[..8])
}

fn message(obj_hash: &[u8; 32], man_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 64);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(obj_hash);
    m.extend_from_slice(man_hash);
    m
}

pub fn signing_key_from_seed_hex(s: &str) -> anyhow::Result<SigningKey> {
    let b = hex::decode(s.trim())?;
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn sign(sk: &SigningKey, object: &[u8], manifest: &[u8]) -> SigFile {
    let oh = sha256(object);
    let mh = sha256(manifest);
    let sig = sk.sign(&message(&oh, &mh));
    SigFile {
        format: FORMAT.into(),
        key_id: key_id(&sk.verifying_key()),
        object_sha256: hex::encode(oh),
        manifest_sha256: hex::encode(mh),
        signature: hex::encode(sig.to_bytes()),
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TrustStore {
    pub fn add(&mut self, vk: VerifyingKey) {
        self.keys.insert(key_id(&vk), vk);
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    /// Load every `*.pub` (hex, 32 bytes) in `dir`.
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let mut ts = TrustStore::default();
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("pub") {
                continue;
            }
            let b = hex::decode(std::fs::read_to_string(&p)?.trim())?;
            let arr: [u8; 32] = b
                .try_into()
                .map_err(|_| anyhow::anyhow!("{}: not 32 bytes", p.display()))?;
            ts.add(VerifyingKey::from_bytes(&arr)?);
        }
        if ts.is_empty() {
            anyhow::bail!("trust store {} has no *.pub keys", dir.display());
        }
        Ok(ts)
    }

    /// Verify `sig_bytes` against the exact object/manifest bytes held in memory.
    /// The hashes inside the signature file are never trusted: they are
    /// recomputed and must match, and the signature is checked over the
    /// recomputed values.
    pub fn verify(
        &self,
        object: &[u8],
        manifest: &[u8],
        sig_bytes: Option<&[u8]>,
    ) -> Result<String, SigError> {
        let raw = sig_bytes.ok_or(SigError::Missing)?;
        let sf: SigFile =
            serde_json::from_slice(raw).map_err(|e| SigError::Malformed(e.to_string()))?;
        if sf.format != FORMAT {
            return Err(SigError::Malformed(format!(
                "unknown format {:?}",
                sf.format
            )));
        }
        let sig_raw = hex::decode(&sf.signature).map_err(|e| SigError::Malformed(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| SigError::Malformed("signature must be 64 bytes".into()))?;
        let vk = self
            .keys
            .get(&sf.key_id)
            .ok_or_else(|| SigError::UnknownKey(sf.key_id.clone()))?;
        let oh = sha256(object);
        let mh = sha256(manifest);
        if hex::encode(oh) != sf.object_sha256 {
            return Err(SigError::ObjectHashMismatch);
        }
        if hex::encode(mh) != sf.manifest_sha256 {
            return Err(SigError::ManifestHashMismatch);
        }
        vk.verify_strict(&message(&oh, &mh), &Signature::from_bytes(&sig_arr))
            .map_err(|_| SigError::BadSignature)?;
        Ok(sf.key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn roundtrip_and_tamper() {
        let k = sk(1);
        let mut ts = TrustStore::default();
        ts.add(k.verifying_key());
        let s = serde_json::to_vec(&sign(&k, b"obj", b"man")).unwrap();
        assert!(ts.verify(b"obj", b"man", Some(&s)).is_ok());
        assert_eq!(
            ts.verify(b"obJ", b"man", Some(&s)),
            Err(SigError::ObjectHashMismatch)
        );
        assert_eq!(
            ts.verify(b"obj", b"maN", Some(&s)),
            Err(SigError::ManifestHashMismatch)
        );
        assert_eq!(ts.verify(b"obj", b"man", None), Err(SigError::Missing));
    }

    #[test]
    fn attacker_rewrites_hash_fields_but_cannot_resign() {
        let k = sk(1);
        let mut ts = TrustStore::default();
        ts.add(k.verifying_key());
        let mut sf = sign(&k, b"obj", b"man");
        sf.object_sha256 = hex::encode(sha256(b"evil"));
        let s = serde_json::to_vec(&sf).unwrap();
        assert_eq!(
            ts.verify(b"evil", b"man", Some(&s)),
            Err(SigError::BadSignature)
        );
    }

    #[test]
    fn untrusted_key() {
        let mut ts = TrustStore::default();
        ts.add(sk(1).verifying_key());
        let s = serde_json::to_vec(&sign(&sk(2), b"o", b"m")).unwrap();
        assert!(matches!(
            ts.verify(b"o", b"m", Some(&s)),
            Err(SigError::UnknownKey(_))
        ));
    }
}
