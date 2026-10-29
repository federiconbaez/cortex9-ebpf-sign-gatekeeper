//! Build fixtures/cases/ and fixtures/index.json from fixtures/bpf-obj/*.o.
//! Re-run after changing the object files; then commit the regenerated cases.

use ebpf_sign_gatekeeper::elf::BpfElf;
use ebpf_sign_gatekeeper::manifest::{Manifest, ProgramDecl};
use ebpf_sign_gatekeeper::scan::{prog_type_for_section, scan_object};
use ebpf_sign_gatekeeper::sig::{key_id, sign, TrustStore, FORMAT};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn honest_manifest(name: &str, obj: &[u8]) -> Manifest {
    let elf = BpfElf::parse(obj).expect("honest object must parse");
    let scan = scan_object(&elf).expect("honest object must scan");
    let mut maps = BTreeSet::new();
    let mut kfuncs = BTreeSet::new();
    let mut globals = BTreeSet::new();
    let mut programs = Vec::new();
    for s in &scan.sections {
        maps.extend(s.maps.iter().cloned());
        kfuncs.extend(s.kfuncs.iter().cloned());
        globals.extend(s.globals.iter().cloned());
        let pt = prog_type_for_section(&s.section)
            .unwrap_or("unknown")
            .to_string();
        programs.push(ProgramDecl {
            section: s.section.clone(),
            prog_type: pt,
            helpers: s.helpers.clone(),
        });
    }
    Manifest {
        name: name.into(),
        programs,
        maps,
        kfuncs,
        globals,
    }
}

fn write_case(root: &Path, id: &str, obj: &[u8], man: &[u8], sig: Option<&[u8]>) {
    let d = root.join("cases").join(id);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("prog.o"), obj).unwrap();
    fs::write(d.join("manifest.json"), man).unwrap();
    let sp = d.join("prog.o.sig");
    if let Some(s) = sig {
        fs::write(&sp, s).unwrap();
    } else if sp.exists() {
        fs::remove_file(&sp).unwrap();
    }
}

fn main() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let obj_dir = root.join("bpf-obj");
    let keys = root.join("keys");
    fs::create_dir_all(&keys)?;
    fs::create_dir_all(root.join("cases"))?;

    // Fixed seeds so regenerating the corpus does not churn every signature.
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let attacker = SigningKey::from_bytes(&[0x13; 32]);
    fs::write(
        keys.join("trusted.pub"),
        hex::encode(sk.verifying_key().as_bytes()),
    )?;
    // attacker.pub is *not* installed in the trust store — only recorded so a
    // reader can see what the "wrong key" fixtures were signed with.
    fs::write(
        keys.join("attacker.seed.hex"),
        hex::encode(attacker.to_bytes()),
    )?;
    fs::write(keys.join("trusted.seed.hex"), hex::encode(sk.to_bytes()))?;
    eprintln!("trust key_id={}", key_id(&sk.verifying_key()));

    let mut index = Vec::new();

    // ---- 20 valid ----
    let mut valids: Vec<PathBuf> = fs::read_dir(&obj_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('v') && n.ends_with(".o"))
                .unwrap_or(false)
        })
        .collect();
    valids.sort();
    assert_eq!(valids.len(), 20, "expected 20 valid .o");
    for p in &valids {
        let stem = p.file_stem().unwrap().to_string_lossy().to_string();
        let obj = fs::read(p)?;
        let man = honest_manifest(&stem, &obj);
        let man_bytes = serde_json::to_vec_pretty(&man)?;
        let sig = serde_json::to_vec_pretty(&sign(&sk, &obj, &man_bytes))?;
        write_case(&root, &stem, &obj, &man_bytes, Some(&sig));
        index.push(json!({"id": stem, "kind": "valid", "expect": "allow"}));
    }

    // ---- 10 lying (honest signature of a dishonest manifest) ----
    let mut lyings: Vec<PathBuf> = fs::read_dir(&obj_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('l') && n.ends_with(".o"))
                .unwrap_or(false)
        })
        .collect();
    lyings.sort();
    assert_eq!(lyings.len(), 10);
    for p in &lyings {
        let stem = p.file_stem().unwrap().to_string_lossy().to_string();
        let obj = fs::read(p)?;
        let mut man = honest_manifest(&stem, &obj);
        let reason: &str = match stem.as_str() {
            "l01_kprobe_hidden_probe_read" => {
                for pr in &mut man.programs {
                    pr.helpers.remove(&113);
                }
                "undeclared_helper"
            }
            "l02_kprobe_hidden_signal" => {
                for pr in &mut man.programs {
                    pr.helpers.remove(&109);
                }
                "undeclared_helper"
            }
            "l03_kprobe_hidden_override" => {
                for pr in &mut man.programs {
                    pr.helpers.remove(&58);
                }
                "undeclared_helper"
            }
            "l04_kprobe_hidden_write_user" => {
                for pr in &mut man.programs {
                    pr.helpers.remove(&36);
                }
                "undeclared_helper"
            }
            "l05_tp_hidden_task" => {
                for pr in &mut man.programs {
                    pr.helpers.remove(&35);
                }
                "undeclared_helper"
            }
            "l06_kprobe_claims_socket" => {
                man.programs[0].prog_type = "socket_filter".into();
                "hook_mismatch"
            }
            "l07_xdp_claims_socket" => {
                man.programs[0].prog_type = "socket_filter".into();
                "hook_mismatch"
            }
            "l08_xdp_hidden_second_prog" => {
                // declare only the xdp program; hide the kprobe that sends a signal
                man.programs.retain(|p| p.section == "xdp");
                "undeclared_section"
            }
            "l09_xdp_subprog_signal" => {
                // declare the xdp entry but not .text (which holds bpf_send_signal)
                // and strip helper 109 from any declaration
                man.programs.retain(|p| p.section == "xdp");
                for pr in &mut man.programs {
                    pr.helpers.remove(&109);
                }
                "undeclared_section"
            }
            "l10_xdp_hidden_map" => {
                man.maps.clear();
                "undeclared_map"
            }
            other => panic!("unknown lying fixture {other}"),
        };
        let man_bytes = serde_json::to_vec_pretty(&man)?;
        let sig = serde_json::to_vec_pretty(&sign(&sk, &obj, &man_bytes))?;
        write_case(&root, &stem, &obj, &man_bytes, Some(&sig));
        index.push(json!({
            "id": stem, "kind": "lying",
            "expect": {"deny": {"reason": reason}}
        }));
    }

    // ---- tampered / unsigned / wrong-key / not-bpf, derived from v01 ----
    let base = fs::read(obj_dir.join("v01_xdp_pass.o"))?;
    let base_man = honest_manifest("v01_xdp_pass", &base);
    let base_man_bytes = serde_json::to_vec_pretty(&base_man)?;
    let good_sig = serde_json::to_vec_pretty(&sign(&sk, &base, &base_man_bytes))?;

    // unsigned
    write_case(&root, "u01_unsigned", &base, &base_man_bytes, None);
    index.push(json!({
        "id": "u01_unsigned", "kind": "unsigned",
        "expect": {"deny": {"reason": "sig_missing"}}
    }));

    // object byte flipped after signing
    let mut tampered = base.clone();
    *tampered.last_mut().unwrap() ^= 0xff;
    write_case(
        &root,
        "t01_object_bitflip",
        &tampered,
        &base_man_bytes,
        Some(&good_sig),
    );
    index.push(json!({
        "id": "t01_object_bitflip", "kind": "tampered",
        "expect": {"deny": {"reason": "sig_object_hash"}}
    }));

    // manifest rewritten after signing (signature still claims old hash)
    let mut evil_man = base_man.clone();
    evil_man.name = "evil".into();
    let evil_bytes = serde_json::to_vec_pretty(&evil_man)?;
    write_case(
        &root,
        "t02_manifest_rewrite",
        &base,
        &evil_bytes,
        Some(&good_sig),
    );
    index.push(json!({
        "id": "t02_manifest_rewrite", "kind": "tampered",
        "expect": {"deny": {"reason": "sig_manifest_hash"}}
    }));

    // attacker rewrote the hash fields and re-signed with a key we don't trust
    let sf = sign(&attacker, &base, &base_man_bytes);
    assert_eq!(sf.format, FORMAT);
    let att_sig = serde_json::to_vec_pretty(&sf)?;
    write_case(
        &root,
        "t03_wrong_key",
        &base,
        &base_man_bytes,
        Some(&att_sig),
    );
    index.push(json!({
        "id": "t03_wrong_key", "kind": "tampered",
        "expect": {"deny": {"reason": "sig_unknown_key"}}
    }));

    // signature bytes corrupted (hash fields still match)
    let mut bad = sign(&sk, &base, &base_man_bytes);
    let mut sb = hex::decode(&bad.signature)?;
    sb[0] ^= 0xff;
    bad.signature = hex::encode(sb);
    let bad_sig = serde_json::to_vec_pretty(&bad)?;
    write_case(
        &root,
        "t04_sig_bitflip",
        &base,
        &base_man_bytes,
        Some(&bad_sig),
    );
    index.push(json!({
        "id": "t04_sig_bitflip", "kind": "tampered",
        "expect": {"deny": {"reason": "sig_bad"}}
    }));

    // truncated signature file
    write_case(
        &root,
        "t05_sig_truncated",
        &base,
        &base_man_bytes,
        Some(b"{not json"),
    );
    index.push(json!({
        "id": "t05_sig_truncated", "kind": "tampered",
        "expect": {"deny": {"reason": "sig_malformed"}}
    }));

    // not BPF, but signed as if it were (ELF x86)
    let x86 = fs::read(obj_dir.join("x01_x86_not_bpf.o"))?;
    // invent a plausible (but wrong) "honest" looking manifest for the signature
    let fake = Manifest {
        name: "x01".into(),
        programs: vec![ProgramDecl {
            section: ".text".into(),
            prog_type: "xdp".into(),
            helpers: BTreeSet::new(),
        }],
        maps: BTreeSet::new(),
        kfuncs: BTreeSet::new(),
        globals: BTreeSet::new(),
    };
    let fake_bytes = serde_json::to_vec_pretty(&fake)?;
    let x86_sig = serde_json::to_vec_pretty(&sign(&sk, &x86, &fake_bytes))?;
    write_case(&root, "x01_x86_not_bpf", &x86, &fake_bytes, Some(&x86_sig));
    index.push(json!({
        "id": "x01_x86_not_bpf", "kind": "not_bpf",
        "expect": {"deny": {"reason": "elf_not_bpf"}}
    }));

    // garbage bytes, signed
    let garbage = fs::read(obj_dir.join("x02_garbage.o"))?;
    let g_sig = serde_json::to_vec_pretty(&sign(&sk, &garbage, &fake_bytes))?;
    write_case(&root, "x02_garbage", &garbage, &fake_bytes, Some(&g_sig));
    index.push(json!({
        "id": "x02_garbage", "kind": "not_bpf",
        "expect": {"deny": {"reason": "elf_malformed"}}
    }));

    // empty trust store check is done in unit tests; here we just write the
    // index and a README for the fixtures.
    fs::write(root.join("index.json"), serde_json::to_vec_pretty(&index)?)?;

    // Sanity: the trust store we just wrote must verify every valid case.
    let ts = TrustStore::load_dir(&keys)?;
    assert_eq!(ts.len(), 1);
    eprintln!(
        "wrote {} cases (valid={} lying={} other={})",
        index.len(),
        20,
        10,
        index.len() - 30
    );
    Ok(())
}
