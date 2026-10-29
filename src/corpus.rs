//! Fixture corpus: expected outcomes and the runner that asserts them.

use crate::gate::{check, Bundle, Deny};
use crate::sig::{SigError, TrustStore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allow,
    Deny { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub kind: String, // valid | tampered | unsigned | lying | not_bpf
    pub expect: Expect,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub kind: String,
    pub expect: Expect,
    pub outcome: String,
    pub deny_code: Option<String>,
    pub gate_ns: u128,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub unauthorized_loads: usize,
    pub valid_allowed: usize,
    pub valid_total: usize,
    pub lying_caught: usize,
    pub lying_total: usize,
    pub max_gate_ns: u128,
    pub cases: Vec<CaseResult>,
}

pub fn trust_from_fixtures(root: &Path) -> anyhow::Result<TrustStore> {
    TrustStore::load_dir(&root.join("keys"))
}

pub fn load_index(root: &Path) -> anyhow::Result<Vec<Case>> {
    let v: Vec<Case> = serde_json::from_slice(&std::fs::read(root.join("index.json"))?)?;
    Ok(v)
}

pub fn run_case(root: &Path, trust: &TrustStore, case: &Case) -> anyhow::Result<CaseResult> {
    let dir = root.join("cases").join(&case.id);
    let bundle = Bundle::read_dir(&dir)?;
    let t0 = Instant::now();
    let decision = check(&bundle, trust);
    let gate_ns = t0.elapsed().as_nanos();
    let (outcome, deny_code) = match &decision {
        Ok(_) => ("allow".into(), None),
        Err(d) => ("deny".into(), Some(d.code())),
    };
    let ok = match (&case.expect, &decision) {
        (Expect::Allow, Ok(_)) => true,
        (Expect::Deny { reason }, Err(d)) => {
            // reason may be a prefix: "undeclared_helper" matches any undeclared_helper
            let code = d.code();
            code == *reason || code.starts_with(reason) || matches_deny(d, reason)
        }
        _ => false,
    };
    Ok(CaseResult {
        id: case.id.clone(),
        kind: case.kind.clone(),
        expect: case.expect.clone(),
        outcome,
        deny_code,
        gate_ns,
        ok,
    })
}

fn matches_deny(d: &Deny, reason: &str) -> bool {
    match (d, reason) {
        (Deny::Signature(SigError::Missing), "sig_missing") => true,
        (Deny::Signature(SigError::ObjectHashMismatch), "sig_object_hash") => true,
        (Deny::Signature(SigError::ManifestHashMismatch), "sig_manifest_hash") => true,
        (Deny::Signature(SigError::BadSignature), "sig_bad") => true,
        (Deny::Signature(SigError::UnknownKey(_)), "sig_unknown_key") => true,
        (Deny::Elf(_), "elf") => true,
        (Deny::Policy(v), r) => v.iter().any(|x| x.code() == r),
        _ => false,
    }
}

pub fn run_corpus(root: &Path) -> anyhow::Result<Report> {
    let trust = trust_from_fixtures(root)?;
    let cases = load_index(root)?;
    let mut results = Vec::with_capacity(cases.len());
    for c in &cases {
        results.push(run_case(root, &trust, c)?);
    }
    let passed = results.iter().filter(|r| r.ok).count();
    let valid_total = results.iter().filter(|r| r.kind == "valid").count();
    let valid_allowed = results
        .iter()
        .filter(|r| r.kind == "valid" && r.outcome == "allow")
        .count();
    let lying_total = results.iter().filter(|r| r.kind == "lying").count();
    let lying_caught = results
        .iter()
        .filter(|r| r.kind == "lying" && r.outcome == "deny")
        .count();
    // An "unauthorized load" in the userspace gate path is: a case that should
    // have been denied but was Allowed. (We never call the loader on Deny.)
    let unauthorized_loads = results
        .iter()
        .filter(|r| matches!(r.expect, Expect::Deny { .. }) && r.outcome == "allow")
        .count();
    Ok(Report {
        total: results.len(),
        passed,
        failed: results.len() - passed,
        unauthorized_loads,
        valid_allowed,
        valid_total,
        lying_caught,
        lying_total,
        max_gate_ns: results.iter().map(|r| r.gate_ns).max().unwrap_or(0),
        cases: results,
    })
}

pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}
