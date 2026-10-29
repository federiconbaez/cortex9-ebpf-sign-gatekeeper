//! ebpf-sign-gatekeeper: a userspace gate that runs *before* `bpf(BPF_PROG_LOAD)`.
//!
//! Pipeline (fail-closed, in this order):
//! 1. read object, manifest and signature **once** into memory ([`gate::Bundle`]);
//! 2. verify the stub ed25519 signature over `sha256(object) || sha256(manifest)`
//!    against a local trust store ([`sig`]);
//! 3. parse the ELF BPF object ([`elf`]) and scan its bytecode ([`scan`]);
//! 4. compare what the bytecode actually does with what the signed manifest
//!    declares ([`policy`]);
//! 5. only on `Allow`, hand the *same in-memory bytes* to a [`loader::Loader`].
//!
//! This is not Sigstore/cosign and it is not an in-kernel LSM: see README.

pub mod corpus;
pub mod elf;
pub mod gate;
pub mod helpers;
pub mod loader;
pub mod manifest;
pub mod policy;
pub mod scan;
pub mod sig;
