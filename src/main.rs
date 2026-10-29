//! CLI for the userspace eBPF signature gatekeeper.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ebpf_sign_gatekeeper::corpus::{fixtures_root, run_corpus, Report};
use ebpf_sign_gatekeeper::gate::{check, gate_and_load, Bundle, Outcome};
use ebpf_sign_gatekeeper::loader::{KernelLoader, RecordingLoader};
use ebpf_sign_gatekeeper::sig::TrustStore;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "ebpf-sign-gatekeeper",
    about = "Verify stub ed25519 signature + manifest, scan BPF bytecode, then (optionally) load"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check a case directory (prog.o + manifest.json + prog.o.sig) against a trust store.
    Check {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        /// After Allow, call bpf(BPF_PROG_LOAD). Fails loudly if the kernel refuses.
        #[arg(long, default_value_t = false)]
        load: bool,
    },
    /// Run the committed fixtures corpus. Exit 1 if any case fails the acceptance criteria.
    Corpus {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Print wall-clock of check() over N iterations of every valid fixture (no bpf load).
    Measure {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, default_value_t = 200)]
        iters: u32,
    },
    /// Positive control for CI: bypass the gate and try to load a *lying* object.
    /// Must succeed on a privileged runner (proving the kernel would have accepted
    /// the undeclared helpers) and fail loudly if CAP_BPF is missing.
    EnforceProbe {
        #[arg(long)]
        object: PathBuf,
        #[arg(long)]
        section: String,
        #[arg(long)]
        prog_type: String,
        #[arg(long, default_value = "GPL")]
        license: String,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::Check { dir, trust, load } => {
            let ts = TrustStore::load_dir(&trust)?;
            let b = Bundle::read_dir(&dir)?;
            if load {
                let mut loader = KernelLoader::default();
                match gate_and_load(&b, &ts, &mut loader) {
                    Outcome::Denied(d) => {
                        eprintln!("DENY {}: {d:?}", d.code());
                        Ok(ExitCode::from(1))
                    }
                    Outcome::Loaded(l) => {
                        println!(
                            "ALLOW+LOAD sections={}",
                            l.iter()
                                .map(|x| format!("{}:{}ns", x.section, x.load_ns))
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    Outcome::LoadFailed(e) => {
                        eprintln!("ALLOW but LOAD FAILED: {e}");
                        Ok(ExitCode::from(3))
                    }
                }
            } else {
                match check(&b, &ts) {
                    Ok(a) => {
                        println!(
                            "ALLOW key_id={} programs={}",
                            a.key_id,
                            a.manifest.programs.len()
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    Err(d) => {
                        eprintln!("DENY {}: {d:?}", d.code());
                        Ok(ExitCode::from(1))
                    }
                }
            }
        }
        Cmd::Corpus { dir, json } => {
            let root = dir.unwrap_or_else(fixtures_root);
            let report = run_corpus(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
            if !accept(&report) {
                bail!(
                    "acceptance failed: unauthorized={} valid={}/{} lying={}/{} failed={}",
                    report.unauthorized_loads,
                    report.valid_allowed,
                    report.valid_total,
                    report.lying_caught,
                    report.lying_total,
                    report.failed
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Measure { dir, iters } => {
            let root = dir.unwrap_or_else(fixtures_root);
            let ts = TrustStore::load_dir(&root.join("keys"))?;
            let index = ebpf_sign_gatekeeper::corpus::load_index(&root)?;
            let mut max_ns = 0u128;
            let mut sum_ns = 0u128;
            let mut n = 0u128;
            for c in index.iter().filter(|c| c.kind == "valid") {
                let b = Bundle::read_dir(&root.join("cases").join(&c.id))?;
                // warm once
                let _ = check(&b, &ts);
                for _ in 0..iters {
                    let t0 = std::time::Instant::now();
                    let d = check(&b, &ts);
                    let ns = t0.elapsed().as_nanos();
                    assert!(d.is_ok(), "valid fixture denied during measure");
                    max_ns = max_ns.max(ns);
                    sum_ns += ns;
                    n += 1;
                }
            }
            let avg = sum_ns.checked_div(n).unwrap_or(0);
            println!("gate_check_ns avg={avg} max={max_ns} samples={n} iters_per_case={iters}");
            println!("reproduce: cargo run --release --quiet -- measure --iters {iters}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::EnforceProbe {
            object,
            section,
            prog_type,
            license,
        } => {
            let bytes =
                std::fs::read(&object).with_context(|| format!("read {}", object.display()))?;
            let elf = ebpf_sign_gatekeeper::elf::BpfElf::parse(&bytes)
                .map_err(|e| anyhow::anyhow!("elf: {e}"))?;
            let sec = elf
                .code_sections()
                .find(|s| s.name == section)
                .ok_or_else(|| anyhow::anyhow!("section {section} not found"))?;
            if !elf.relocs.is_empty() {
                bail!("object has relocations; enforce-probe needs a relocation-free .o");
            }
            let pt = ebpf_sign_gatekeeper::loader::prog_type_id(&prog_type)
                .ok_or_else(|| anyhow::anyhow!("unknown prog_type {prog_type}"))?;
            match ebpf_sign_gatekeeper::loader::raw_prog_load(
                &section,
                pt,
                elf.section_bytes(sec),
                &license,
            ) {
                Ok(l) => {
                    println!(
                        "ENFORCE_PROBE_OK section={} fd={} load_ns={}",
                        l.section, l.fd, l.load_ns
                    );
                    // SAFETY: we own the fd returned by the kernel.
                    unsafe { libc::close(l.fd) };
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("ENFORCE_PROBE_FAIL: {e}");
                    // Distinguish "no CAP_BPF" from "verifier rejected".
                    Ok(ExitCode::from(3))
                }
            }
        }
    }
}

fn print_report(r: &Report) {
    println!(
        "corpus: {}/{} ok | unauthorized_loads={} | valid_allowed={}/{} | lying_caught={}/{} | max_gate_ns={}",
        r.passed,
        r.total,
        r.unauthorized_loads,
        r.valid_allowed,
        r.valid_total,
        r.lying_caught,
        r.lying_total,
        r.max_gate_ns
    );
    for c in &r.cases {
        let mark = if c.ok { "PASS" } else { "FAIL" };
        println!(
            "  [{mark}] {} ({}) outcome={} deny={:?} gate_ns={}",
            c.id, c.kind, c.outcome, c.deny_code, c.gate_ns
        );
    }
}

fn accept(r: &Report) -> bool {
    r.failed == 0
        && r.unauthorized_loads == 0
        && r.valid_allowed == r.valid_total
        && r.valid_total > 0
        && r.lying_caught == r.lying_total
        && r.lying_total > 0
}

#[allow(dead_code)]
fn _recording_used_in_tests() {
    let _ = RecordingLoader::default();
}
