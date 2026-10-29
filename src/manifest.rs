//! Manifest: what the signer *declares* the object does.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub programs: Vec<ProgramDecl>,
    #[serde(default)]
    pub maps: BTreeSet<String>,
    #[serde(default)]
    pub kfuncs: BTreeSet<String>,
    #[serde(default)]
    pub globals: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgramDecl {
    pub section: String,
    pub prog_type: String,
    #[serde(default)]
    pub helpers: BTreeSet<i32>,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}
