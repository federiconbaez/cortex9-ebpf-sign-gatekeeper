//! The gate: signature → ELF parse → bytecode scan → manifest comparison.
//! Loading is only reachable through [`gate_and_load`], and only on `Allow`.

use crate::elf::{BpfElf, ElfError};
use crate::loader::{LoadError, Loader};
use crate::manifest::Manifest;
use crate::policy::{compare, Violation};
use crate::scan::{scan_object, ObjectScan};
use crate::sig::{SigError, TrustStore};
use std::path::Path;

pub const OBJECT_FILE: &str = "prog.o";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const SIG_FILE: &str = "prog.o.sig";

/// Everything the gate looks at, read once. The loader receives these same
/// bytes, so there is no re-read of the path between check and load.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub object: Vec<u8>,
    pub manifest: Vec<u8>,
    pub sig: Option<Vec<u8>>,
}

impl Bundle {
    pub fn read_dir(dir: &Path) -> std::io::Result<Self> {
        let sig_path = dir.join(SIG_FILE);
        Ok(Bundle {
            object: std::fs::read(dir.join(OBJECT_FILE))?,
            manifest: std::fs::read(dir.join(MANIFEST_FILE))?,
            sig: if sig_path.exists() {
                Some(std::fs::read(sig_path)?)
            } else {
                None
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deny {
    Signature(SigError),
    Manifest(String),
    Elf(ElfError),
    Policy(Vec<Violation>),
}

impl Deny {
    /// Stable short code used by the corpus labels.
    pub fn code(&self) -> String {
        match self {
            Deny::Signature(e) => match e {
                SigError::Missing => "sig_missing".into(),
                SigError::Malformed(_) => "sig_malformed".into(),
                SigError::UnknownKey(_) => "sig_unknown_key".into(),
                SigError::ObjectHashMismatch => "sig_object_hash".into(),
                SigError::ManifestHashMismatch => "sig_manifest_hash".into(),
                SigError::BadSignature => "sig_bad".into(),
            },
            Deny::Manifest(_) => "manifest_malformed".into(),
            Deny::Elf(ElfError::NotBpf { .. }) => "elf_not_bpf".into(),
            Deny::Elf(_) => "elf_malformed".into(),
            Deny::Policy(v) => v
                .first()
                .map(|x| x.code().to_string())
                .unwrap_or_else(|| "policy".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Allowed {
    pub key_id: String,
    pub manifest: Manifest,
    pub scan: ObjectScan,
}

pub type Decision = Result<Allowed, Deny>;

pub fn check(b: &Bundle, trust: &TrustStore) -> Decision {
    // 1. signature first: nothing unsigned is parsed beyond the sig file itself
    let key_id = trust
        .verify(&b.object, &b.manifest, b.sig.as_deref())
        .map_err(Deny::Signature)?;
    // 2. manifest (signed, but still untrusted input to the parser)
    let manifest = Manifest::parse(&b.manifest).map_err(Deny::Manifest)?;
    // 3. ELF + bytecode
    let elf = BpfElf::parse(&b.object).map_err(Deny::Elf)?;
    let scan = scan_object(&elf).map_err(Deny::Elf)?;
    // 4. declared vs actual
    let v = compare(&manifest, &scan);
    if !v.is_empty() {
        return Err(Deny::Policy(v));
    }
    Ok(Allowed {
        key_id,
        manifest,
        scan,
    })
}

#[derive(Debug)]
pub enum Outcome {
    Denied(Deny),
    Loaded(Vec<crate::loader::Loaded>),
    LoadFailed(LoadError),
}

/// The only path from a bundle to the loader.
pub fn gate_and_load(b: &Bundle, trust: &TrustStore, loader: &mut dyn Loader) -> Outcome {
    match check(b, trust) {
        Err(d) => Outcome::Denied(d),
        Ok(a) => match loader.load(&b.object, &a) {
            Ok(l) => Outcome::Loaded(l),
            Err(e) => Outcome::LoadFailed(e),
        },
    }
}
