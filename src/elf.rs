//! Minimal, bounds-checked ELF64 little-endian parser for relocatable BPF
//! objects (`clang -target bpf -c`). Anything else is rejected.

use std::fmt;

pub const EM_BPF: u16 = 247;
const SHT_SYMTAB: u32 = 2;
const SHT_REL: u32 = 9;
const SHF_EXECINSTR: u64 = 0x4;
const SHN_UNDEF: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    NotElf,
    NotElf64Le,
    NotBpf { machine: u16 },
    NotRelocatable { e_type: u16 },
    OutOfBounds(&'static str),
    Malformed(String),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::NotElf => write!(f, "not an ELF file"),
            ElfError::NotElf64Le => write!(f, "not ELF64 little-endian"),
            ElfError::NotBpf { machine } => write!(f, "e_machine={machine}, expected EM_BPF (247)"),
            ElfError::NotRelocatable { e_type } => write!(f, "e_type={e_type}, expected ET_REL"),
            ElfError::OutOfBounds(w) => write!(f, "out of bounds: {w}"),
            ElfError::Malformed(m) => write!(f, "malformed: {m}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub index: usize,
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub offset: usize,
    pub size: usize,
    pub link: u32,
    pub info: u32,
    pub entsize: u64,
}

impl Section {
    pub fn is_exec(&self) -> bool {
        self.flags & SHF_EXECINSTR != 0
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub shndx: u16,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct Reloc {
    /// index of the section the relocation applies to
    pub target_section: usize,
    pub offset: u64,
    pub sym: usize,
    pub r_type: u32,
}

#[derive(Debug, Clone)]
pub struct BpfElf<'a> {
    pub data: &'a [u8],
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub relocs: Vec<Reloc>,
}

fn rd<const N: usize>(d: &[u8], off: usize, what: &'static str) -> Result<[u8; N], ElfError> {
    d.get(off..off.checked_add(N).ok_or(ElfError::OutOfBounds(what))?)
        .ok_or(ElfError::OutOfBounds(what))
        .map(|s| s.try_into().unwrap())
}
fn u16le(d: &[u8], o: usize, w: &'static str) -> Result<u16, ElfError> {
    Ok(u16::from_le_bytes(rd::<2>(d, o, w)?))
}
fn u32le(d: &[u8], o: usize, w: &'static str) -> Result<u32, ElfError> {
    Ok(u32::from_le_bytes(rd::<4>(d, o, w)?))
}
fn u64le(d: &[u8], o: usize, w: &'static str) -> Result<u64, ElfError> {
    Ok(u64::from_le_bytes(rd::<8>(d, o, w)?))
}

fn cstr(d: &[u8], strtab: &Section, off: u32) -> Result<String, ElfError> {
    let start = strtab
        .offset
        .checked_add(off as usize)
        .ok_or(ElfError::OutOfBounds("strtab"))?;
    let end_tab = strtab.offset + strtab.size;
    if start >= end_tab {
        return Err(ElfError::OutOfBounds("string offset"));
    }
    let bytes = &d[start..end_tab];
    let n = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| ElfError::Malformed("unterminated string".into()))?;
    String::from_utf8(bytes[..n].to_vec()).map_err(|_| ElfError::Malformed("non-utf8 name".into()))
}

impl<'a> BpfElf<'a> {
    pub fn parse(d: &'a [u8]) -> Result<Self, ElfError> {
        if d.len() < 4 || &d[..4] != b"\x7fELF" {
            return Err(ElfError::NotElf);
        }
        if d.len() < 64 || d[4] != 2 || d[5] != 1 {
            return Err(ElfError::NotElf64Le);
        }
        let e_type = u16le(d, 16, "e_type")?;
        let machine = u16le(d, 18, "e_machine")?;
        if machine != EM_BPF {
            return Err(ElfError::NotBpf { machine });
        }
        if e_type != 1 {
            return Err(ElfError::NotRelocatable { e_type });
        }
        let shoff = u64le(d, 40, "e_shoff")? as usize;
        let shentsize = u16le(d, 58, "e_shentsize")? as usize;
        let shnum = u16le(d, 60, "e_shnum")? as usize;
        let shstrndx = u16le(d, 62, "e_shstrndx")? as usize;
        if shentsize != 64 || shnum == 0 || shstrndx >= shnum {
            return Err(ElfError::Malformed("section header table".into()));
        }
        let mut raw = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let b = shoff
                .checked_add(i * 64)
                .ok_or(ElfError::OutOfBounds("shdr"))?;
            let s = Section {
                index: i,
                name: String::new(),
                sh_type: u32le(d, b + 4, "sh_type")?,
                flags: u64le(d, b + 8, "sh_flags")?,
                offset: u64le(d, b + 24, "sh_offset")? as usize,
                size: u64le(d, b + 32, "sh_size")? as usize,
                link: u32le(d, b + 40, "sh_link")?,
                info: u32le(d, b + 44, "sh_info")?,
                entsize: u64le(d, b + 56, "sh_entsize")?,
            };
            let name_off = u32le(d, b, "sh_name")?;
            // NOBITS (8) sections have no file bytes
            if s.sh_type != 8 && s.sh_type != 0 {
                let end = s
                    .offset
                    .checked_add(s.size)
                    .ok_or(ElfError::OutOfBounds("section"))?;
                if end > d.len() {
                    return Err(ElfError::OutOfBounds("section data"));
                }
            }
            raw.push((name_off, s));
        }
        let strtab = raw[shstrndx].1.clone();
        let mut sections = Vec::with_capacity(shnum);
        for (name_off, mut s) in raw {
            s.name = if s.sh_type == 0 {
                String::new()
            } else {
                cstr(d, &strtab, name_off)?
            };
            sections.push(s);
        }

        let mut symbols = Vec::new();
        if let Some(symtab) = sections.iter().find(|s| s.sh_type == SHT_SYMTAB) {
            let strt = sections
                .get(symtab.link as usize)
                .ok_or_else(|| ElfError::Malformed("symtab link".into()))?
                .clone();
            if symtab.size % 24 != 0 {
                return Err(ElfError::Malformed("symtab size".into()));
            }
            for i in 0..symtab.size / 24 {
                let b = symtab.offset + i * 24;
                let name = cstr(d, &strt, u32le(d, b, "st_name")?)?;
                symbols.push(Symbol {
                    name,
                    shndx: u16le(d, b + 6, "st_shndx")?,
                    value: u64le(d, b + 8, "st_value")?,
                });
            }
        }

        let mut relocs = Vec::new();
        for s in sections.iter().filter(|s| s.sh_type == SHT_REL) {
            if s.size % 16 != 0 {
                return Err(ElfError::Malformed(format!("{}: rel size", s.name)));
            }
            if s.info as usize >= sections.len() {
                return Err(ElfError::Malformed(format!("{}: sh_info", s.name)));
            }
            for i in 0..s.size / 16 {
                let b = s.offset + i * 16;
                let info = u64le(d, b + 8, "r_info")?;
                let sym = (info >> 32) as usize;
                if sym >= symbols.len() {
                    return Err(ElfError::Malformed(format!("{}: bad symbol index", s.name)));
                }
                relocs.push(Reloc {
                    target_section: s.info as usize,
                    offset: u64le(d, b, "r_offset")?,
                    sym,
                    r_type: info as u32,
                });
            }
        }
        Ok(BpfElf {
            data: d,
            sections,
            symbols,
            relocs,
        })
    }

    pub fn section_bytes(&self, s: &Section) -> &'a [u8] {
        &self.data[s.offset..s.offset + s.size]
    }

    /// Executable sections that contain at least one instruction.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_exec() && s.size > 0)
    }

    pub fn license(&self) -> Option<String> {
        let s = self.sections.iter().find(|s| s.name == "license")?;
        let b = self.section_bytes(s);
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8(b[..n].to_vec()).ok()
    }

    /// Name of the section a symbol is defined in, or None if undefined/extern.
    pub fn symbol_section(&self, sym: &Symbol) -> Option<&Section> {
        if sym.shndx == SHN_UNDEF || sym.shndx >= 0xff00 {
            return None;
        }
        self.sections.get(sym.shndx as usize)
    }
}
