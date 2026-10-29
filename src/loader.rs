//! Loaders. [`KernelLoader`] issues a raw `bpf(BPF_PROG_LOAD)` for each
//! program section of a *relocation-free* object (no maps/globals/subprogs/
//! CO-RE): those are exactly the objects whose loaded bytes equal the signed
//! bytes. Anything that would need libbpf-style relocation is refused
//! (fail-closed), not silently loaded.

use crate::elf::BpfElf;
use crate::gate::Allowed;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Loaded {
    pub section: String,
    pub fd: i32,
    pub load_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Unsupported(String),
    Kernel {
        section: String,
        errno: i32,
        log: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Unsupported(s) => write!(f, "unsupported for load: {s}"),
            LoadError::Kernel {
                section,
                errno,
                log,
            } => write!(
                f,
                "bpf(BPF_PROG_LOAD) {section}: errno {errno} ({}); verifier log: {log}",
                std::io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

pub trait Loader {
    fn load(&mut self, object: &[u8], allowed: &Allowed) -> Result<Vec<Loaded>, LoadError>;
}

/// Test loader: records what it was asked to load, never touches the kernel.
#[derive(Debug, Default)]
pub struct RecordingLoader {
    pub calls: Vec<String>,
}

impl Loader for RecordingLoader {
    fn load(&mut self, _object: &[u8], a: &Allowed) -> Result<Vec<Loaded>, LoadError> {
        self.calls.push(a.manifest.name.clone());
        Ok(vec![])
    }
}

pub fn prog_type_id(t: &str) -> Option<u32> {
    // enum bpf_prog_type, include/uapi/linux/bpf.h
    Some(match t {
        "socket_filter" => 1,
        "kprobe" => 2,
        "sched_cls" => 3,
        "tracepoint" => 5,
        "xdp" => 6,
        _ => return None,
    })
}

#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

const BPF_PROG_LOAD: libc::c_long = 5;

/// Raw `bpf(BPF_PROG_LOAD)` of one instruction buffer. Public so the CI
/// enforce job can run the *positive control* (load a lying object with the
/// gate bypassed, to show the kernel itself would have accepted it).
pub fn raw_prog_load(
    section: &str,
    prog_type: u32,
    insns: &[u8],
    license: &str,
) -> Result<Loaded, LoadError> {
    let lic = std::ffi::CString::new(license)
        .map_err(|_| LoadError::Unsupported("license has NUL".into()))?;
    let mut log = vec![0u8; 64 * 1024];
    let mut attr = ProgLoadAttr {
        prog_type,
        insn_cnt: (insns.len() / 8) as u32,
        insns: insns.as_ptr() as u64,
        license: lic.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        ..Default::default()
    };
    let name: String = section
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(15)
        .collect();
    attr.prog_name[..name.len()].copy_from_slice(name.as_bytes());
    let t0 = std::time::Instant::now();
    // SAFETY: attr points to valid memory for the duration of the call; all
    // pointers inside it (insns, license, log) outlive the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &mut attr as *mut ProgLoadAttr,
            std::mem::size_of::<ProgLoadAttr>(),
        )
    };
    let load_ns = t0.elapsed().as_nanos();
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let n = log.iter().position(|&b| b == 0).unwrap_or(0);
        return Err(LoadError::Kernel {
            section: section.into(),
            errno,
            log: String::from_utf8_lossy(&log[..n]).trim().to_string(),
        });
    }
    Ok(Loaded {
        section: section.into(),
        fd: fd as i32,
        load_ns,
    })
}

/// Loads into the running kernel and closes the fds immediately (nothing is
/// attached). Requires CAP_BPF (+ CAP_PERFMON / CAP_NET_ADMIN per type).
#[derive(Debug, Default)]
pub struct KernelLoader {
    pub keep_fds: bool,
}

impl Loader for KernelLoader {
    fn load(&mut self, object: &[u8], a: &Allowed) -> Result<Vec<Loaded>, LoadError> {
        let elf = BpfElf::parse(object).map_err(|e| LoadError::Unsupported(e.to_string()))?;
        if let Some(s) = a.scan.sections.iter().find(|s| s.reloc_count > 0) {
            return Err(LoadError::Unsupported(format!(
                "{}: {} relocation(s); this loader only handles relocation-free objects",
                s.section, s.reloc_count
            )));
        }
        let license = a.scan.license.clone().unwrap_or_default();
        let mut out = Vec::new();
        for decl in &a.manifest.programs {
            if decl.prog_type == "subprog" {
                return Err(LoadError::Unsupported("subprograms need linking".into()));
            }
            let pt = prog_type_id(&decl.prog_type)
                .ok_or_else(|| LoadError::Unsupported(decl.prog_type.clone()))?;
            let sec = elf
                .code_sections()
                .find(|s| s.name == decl.section)
                .ok_or_else(|| LoadError::Unsupported(format!("{} vanished", decl.section)))?;
            let l = raw_prog_load(&decl.section, pt, elf.section_bytes(sec), &license)?;
            if !self.keep_fds {
                // SAFETY: fd was just returned by the kernel and is owned here.
                unsafe { libc::close(l.fd) };
            }
            out.push(l);
        }
        Ok(out)
    }
}
