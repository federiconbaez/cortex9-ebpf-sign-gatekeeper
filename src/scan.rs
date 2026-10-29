//! Bytecode scan: what each code section *actually* does, independent of what
//! the manifest claims. Works on the ELF object; nothing is loaded.

use crate::elf::{BpfElf, ElfError};
use std::collections::BTreeSet;

pub const BPF_CALL_OP: u8 = 0x85; // BPF_JMP | BPF_CALL | BPF_K
pub const BPF_CALLX_OP: u8 = 0x8d; // BPF_JMP | BPF_CALL | BPF_X
pub const BPF_LD_IMM64_OP: u8 = 0x18; // BPF_LD | BPF_DW | BPF_IMM
pub const PSEUDO_CALL: u8 = 1;
pub const PSEUDO_KFUNC_CALL: u8 = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectionScan {
    pub section: String,
    pub insn_count: usize,
    pub helpers: BTreeSet<i32>,
    /// bpf-to-bpf calls (src_reg=1); targets are other code sections
    pub subprog_calls: usize,
    /// calls with src_reg=2 (kfunc by BTF id) or relocations to undefined symbols
    pub kfuncs: BTreeSet<String>,
    /// map references (relocations into `maps` / `.maps`, or ld_imm64 pseudo map srcs)
    pub maps: BTreeSet<String>,
    /// relocations into .data/.rodata/.bss
    pub globals: BTreeSet<String>,
    pub indirect_calls: usize,
    /// number of relocation records that target this section
    pub reloc_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ObjectScan {
    pub sections: Vec<SectionScan>,
    pub license: Option<String>,
}

impl ObjectScan {
    pub fn get(&self, name: &str) -> Option<&SectionScan> {
        self.sections.iter().find(|s| s.section == name)
    }
}

pub fn scan_insns(section: &str, code: &[u8]) -> Result<SectionScan, ElfError> {
    if code.len() % 8 != 0 {
        return Err(ElfError::Malformed(format!(
            "{section}: size {} not a multiple of 8",
            code.len()
        )));
    }
    let mut out = SectionScan {
        section: section.to_string(),
        insn_count: code.len() / 8,
        ..Default::default()
    };
    let mut i = 0;
    let n = code.len() / 8;
    while i < n {
        let b = &code[i * 8..i * 8 + 8];
        let op = b[0];
        let src = b[1] >> 4;
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        match op {
            BPF_LD_IMM64_OP => {
                if i + 1 >= n {
                    return Err(ElfError::Malformed(format!(
                        "{section}: truncated ld_imm64 at insn {i}"
                    )));
                }
                // BPF_PSEUDO_MAP_FD=1, MAP_VALUE=2, MAP_IDX=5, MAP_IDX_VALUE=6
                if matches!(src, 1 | 2 | 5 | 6) {
                    out.maps.insert(format!("pseudo-src{src}@insn{i}"));
                }
                if src == 3 || src == 4 {
                    out.kfuncs.insert(format!("ld_imm64-src{src}-imm{imm}"));
                }
                i += 2;
                continue;
            }
            BPF_CALL_OP => match src {
                0 => {
                    out.helpers.insert(imm);
                }
                PSEUDO_CALL => out.subprog_calls += 1,
                PSEUDO_KFUNC_CALL => {
                    out.kfuncs.insert(format!("btf_id:{imm}"));
                }
                other => {
                    return Err(ElfError::Malformed(format!(
                        "{section}: call with unknown src_reg {other} at insn {i}"
                    )))
                }
            },
            BPF_CALLX_OP => out.indirect_calls += 1,
            _ => {}
        }
        i += 1;
    }
    Ok(out)
}

pub fn scan_object(elf: &BpfElf) -> Result<ObjectScan, ElfError> {
    let mut sections = Vec::new();
    for s in elf.code_sections() {
        let mut sc = scan_insns(&s.name, elf.section_bytes(s))?;
        for r in elf.relocs.iter().filter(|r| r.target_section == s.index) {
            sc.reloc_count += 1;
            let sym = &elf.symbols[r.sym];
            match elf.symbol_section(sym) {
                None => {
                    // extern (kfunc / ksym / kconfig): resolved by libbpf at load time
                    sc.kfuncs.insert(format!("extern:{}", sym.name));
                }
                Some(t) if t.is_exec() => {} // subprog call/address: already counted
                Some(t) if t.name == "maps" || t.name == ".maps" => {
                    sc.maps.insert(sym.name.clone());
                }
                Some(t)
                    if t.name.starts_with(".data")
                        || t.name.starts_with(".rodata")
                        || t.name.starts_with(".bss") =>
                {
                    sc.globals.insert(if sym.name.is_empty() {
                        t.name.clone()
                    } else {
                        sym.name.clone()
                    });
                }
                Some(t) => {
                    sc.globals.insert(format!("other:{}", t.name));
                }
            }
        }
        // ld_imm64 pseudo-map srcs are only a fallback; relocations name the map
        if sc.maps.iter().any(|m| !m.starts_with("pseudo-")) {
            sc.maps.retain(|m| !m.starts_with("pseudo-"));
        }
        sections.push(sc);
    }
    Ok(ObjectScan {
        sections,
        license: elf.license(),
    })
}

/// Program type implied by the ELF section name (libbpf conventions, subset).
pub fn prog_type_for_section(name: &str) -> Option<&'static str> {
    if name == ".text" {
        return Some("subprog");
    }
    let base = name.split('/').next().unwrap_or(name);
    Some(match base {
        "xdp" => "xdp",
        "socket" => "socket_filter",
        "tc" | "classifier" => "sched_cls",
        "kprobe" | "kretprobe" => "kprobe",
        "tracepoint" | "tp" => "tracepoint",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(op: u8, src: u8, imm: i32) -> [u8; 8] {
        let i = imm.to_le_bytes();
        [op, src << 4, 0, 0, i[0], i[1], i[2], i[3]]
    }

    #[test]
    fn helper_kfunc_subprog_and_ldimm64() {
        let mut code = Vec::new();
        code.extend(insn(BPF_CALL_OP, 0, 5));
        code.extend(insn(BPF_CALL_OP, PSEUDO_KFUNC_CALL, 4242));
        code.extend(insn(BPF_CALL_OP, PSEUDO_CALL, -1));
        // ld_imm64 whose second half looks like a call: must be skipped
        code.extend(insn(BPF_LD_IMM64_OP, 1, 0));
        code.extend(insn(BPF_CALL_OP, 0, 113));
        code.extend(insn(0x95, 0, 0));
        let s = scan_insns("xdp", &code).unwrap();
        assert_eq!(s.helpers.iter().copied().collect::<Vec<_>>(), vec![5]);
        assert!(s.kfuncs.contains("btf_id:4242"));
        assert_eq!(s.subprog_calls, 1);
        assert_eq!(s.maps.len(), 1);
    }

    #[test]
    fn truncated_ld_imm64_is_malformed() {
        let code = insn(BPF_LD_IMM64_OP, 0, 0);
        assert!(scan_insns("xdp", &code).is_err());
    }

    #[test]
    fn odd_size_is_malformed() {
        assert!(scan_insns("xdp", &[0u8; 7]).is_err());
    }

    #[test]
    fn section_names() {
        assert_eq!(prog_type_for_section("xdp"), Some("xdp"));
        assert_eq!(prog_type_for_section("kprobe/do_x"), Some("kprobe"));
        assert_eq!(prog_type_for_section("tracepoint/a/b"), Some("tracepoint"));
        assert_eq!(prog_type_for_section("lsm/bprm"), None);
    }
}
