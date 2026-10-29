//! Compare the signed manifest against the bytecode scan. Every mismatch is a
//! deny reason; the manifest must describe the object exactly (no undeclared
//! sections, helpers, maps, kfuncs or globals; no declared-but-absent sections).

use crate::manifest::Manifest;
use crate::scan::{prog_type_for_section, ObjectScan};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    UndeclaredSection(String),
    MissingSection(String),
    UnknownHook(String),
    HookMismatch {
        section: String,
        declared: String,
        actual: String,
    },
    UndeclaredHelper {
        section: String,
        id: i32,
    },
    UndeclaredKfunc {
        section: String,
        what: String,
    },
    UndeclaredMap {
        section: String,
        map: String,
    },
    UndeclaredGlobal {
        section: String,
        what: String,
    },
    IndirectCall(String),
    NoLicense,
}

impl Violation {
    pub fn code(&self) -> &'static str {
        match self {
            Violation::UndeclaredSection(_) => "undeclared_section",
            Violation::MissingSection(_) => "missing_section",
            Violation::UnknownHook(_) => "unknown_hook",
            Violation::HookMismatch { .. } => "hook_mismatch",
            Violation::UndeclaredHelper { .. } => "undeclared_helper",
            Violation::UndeclaredKfunc { .. } => "undeclared_kfunc",
            Violation::UndeclaredMap { .. } => "undeclared_map",
            Violation::UndeclaredGlobal { .. } => "undeclared_global",
            Violation::IndirectCall(_) => "indirect_call",
            Violation::NoLicense => "no_license",
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::UndeclaredHelper { section, id } => write!(
                f,
                "{section}: calls helper {id} ({}) not declared in manifest",
                crate::helpers::helper_name(*id)
            ),
            Violation::HookMismatch {
                section,
                declared,
                actual,
            } => write!(
                f,
                "{section}: manifest says {declared}, section implies {actual}"
            ),
            other => write!(f, "{other:?}"),
        }
    }
}

pub fn compare(m: &Manifest, scan: &ObjectScan) -> Vec<Violation> {
    let mut v = Vec::new();
    if scan.license.is_none() {
        v.push(Violation::NoLicense);
    }
    for decl in &m.programs {
        if scan.get(&decl.section).is_none() {
            v.push(Violation::MissingSection(decl.section.clone()));
        }
    }
    for s in &scan.sections {
        let Some(decl) = m.programs.iter().find(|p| p.section == s.section) else {
            v.push(Violation::UndeclaredSection(s.section.clone()));
            continue;
        };
        match prog_type_for_section(&s.section) {
            None => v.push(Violation::UnknownHook(s.section.clone())),
            Some(actual) if actual != decl.prog_type => v.push(Violation::HookMismatch {
                section: s.section.clone(),
                declared: decl.prog_type.clone(),
                actual: actual.into(),
            }),
            Some(_) => {}
        }
        for id in s.helpers.difference(&decl.helpers) {
            v.push(Violation::UndeclaredHelper {
                section: s.section.clone(),
                id: *id,
            });
        }
        for k in s.kfuncs.iter().filter(|k| !m.kfuncs.contains(*k)) {
            v.push(Violation::UndeclaredKfunc {
                section: s.section.clone(),
                what: k.clone(),
            });
        }
        for mp in s.maps.iter().filter(|x| !m.maps.contains(*x)) {
            v.push(Violation::UndeclaredMap {
                section: s.section.clone(),
                map: mp.clone(),
            });
        }
        for g in s.globals.iter().filter(|x| !m.globals.contains(*x)) {
            v.push(Violation::UndeclaredGlobal {
                section: s.section.clone(),
                what: g.clone(),
            });
        }
        if s.indirect_calls > 0 {
            v.push(Violation::IndirectCall(s.section.clone()));
        }
    }
    v
}
