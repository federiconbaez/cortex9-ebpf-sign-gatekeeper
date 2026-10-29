# ebpf-sign-gatekeeper

Userspace gate that verifies a **stub** signature + a declarative manifest of
an eBPF ELF object, **scans the bytecode**, and only then hands the same
in-memory bytes to a loader. It is a companion idea to in-kernel BPF signing /
LSM gatekeepers (Hornet, kernel BPF signing); it is **not** a replacement for
them and it does **not** claim Sigstore/cosign interoperability.

```
┌────────────┐   Bundle{object,manifest,sig}   ┌──────────┐
│  case dir  │ ───────────────────────────────►│   gate   │──Deny──► exit 1
└────────────┘                                 │ check()  │
                                               └────┬─────┘
                                                    │ Allow (same bytes)
                                                    ▼
                                               ┌──────────┐
                                               │  loader  │──► bpf(BPF_PROG_LOAD)
                                               └──────────┘     (CI only)
```

## What this is / is not

| Claim | Status |
|---|---|
| Stub ed25519 over `sha256(object) \|\| sha256(manifest)` | **Implemented**, format `ebpf-sign-gatekeeper/stub-ed25519/v1` |
| Bytecode helper / section / map / kfunc scan vs. signed manifest | **Implemented** |
| 0 unauthorized loads in the userspace gate path | **Measured** on the committed corpus |
| Interop with Sigstore / cosign / Rekor | **Not implemented, not claimed** |
| In-kernel LSM (Hornet) or kernel BPF signing | **Not implemented**; see citations below |
| Survives CO-RE / map-fd / ksym rewrite of the *loaded* bytes | **Out of scope** for the day-MVP loader (relocation-free objects only) |

### Citations (opened this turn)

- **Hornet LSM** (Blaise Boscaccy, LSF/MM/BPF 2025): in-kernel C LSM that
  verifies a PKCS#7 signature of light-skeleton / static eBPF instruction+map
  buffers at the `BPF_PROG_LOAD` LSM hook, and freezes maps to stop
  inter-syscall TOCTOU. Slides:
  <https://bpfconf.ebpf.io/bpfconf2025/bpfconf2025_material/hornet-lsm.pdf>
  (fetched 2026-10-29). This repo is *userspace* and does not attach an LSM.
- **Kernel BPF signing** docs:
  <https://docs.kernel.org/bpf/signing.html> (fetched 2026-10-29). The signed
  unit is the light-skeleton loader (`Sig(I_loader || D_meta)`), not the
  relocated target program. Our stub signs the *ELF object bytes* the
  developer built; that is a weaker, different contract, and the README says
  so on purpose.

## Signature format (stub)

```
message  = b"EBPF-SIGN-GATEKEEPER-V1\0" || sha256(object) || sha256(manifest)
sig file = JSON { format, key_id, object_sha256, manifest_sha256, signature }
key_id   = hex(sha256(verifying_key)[:8])
```

The hashes inside the signature file are **recomputed** from the bytes held in
memory; rewriting them without the private key fails `BadSignature`. The trust
store is a directory of `*.pub` (hex-encoded 32-byte ed25519 verifying keys).
The committed fixtures use a fixed seed so regenerating the corpus is
deterministic (`fixtures/keys/trusted.seed.hex` — **test key only**).

## Manifest

```json
{
  "name": "v03_xdp_ktime",
  "programs": [
    { "section": "xdp", "prog_type": "xdp", "helpers": [5] }
  ],
  "maps": [],
  "kfuncs": [],
  "globals": []
}
```

A lying manifest is one that is *correctly signed* but under-declares what the
bytecode does (helper, section, map, hook). The gate compares the scan of the
object against the manifest and denies on any undeclared capability.

## Acceptance (fixtures)

| Criterion | Target | How |
|---|---|---|
| Fixtures | ≥ 20 BPF `.o` + signed/unsigned/tampered/lying cases | `fixtures/index.json` |
| Unauthorized loads (userspace gate) | **0** | deny never calls the loader |
| Valid signed pass | **100 %** | `kind=valid` → `Allow` |
| Lying-manifest caught by bytecode scan | **100 %** | `kind=lying` → `Deny` |
| Gate overhead | **&lt; 20 ms** (release avg ≈ 37 µs, max ≪ 1 ms on this box) | `cargo run --release --quiet -- measure --iters 500` |

Reproduce:

```bash
cargo test --workspace
cargo run --quiet -- corpus
cargo run --release --quiet -- measure --iters 500
```

## CI

- `ci.yml` — `fmt`, `clippy -D warnings`, `cargo test`, `corpus`, `measure`.
  Needs **no** CAP_BPF. Safe on this box (`unprivileged_bpf_disabled=2`).
- `enforce.yml` — real `bpf(BPF_PROG_LOAD)`.
  1. Positive control: load a *lying* object **with the gate bypassed**
     (`enforce-probe`) — proves the kernel would have accepted it.
  2. Gate denies the same lying case (no load attempted).
  3. Gate allows a valid case **and** loads it (`--load`).
  If the runner cannot load BPF, the job **fails** (never a silent skip).

## Limits (honest)

- Stub crypto, not Sigstore. Do not point a cosign verifier at these `.sig` files.
- `KernelLoader` only loads **relocation-free** objects (no maps, no subprogram
  calls that need linking, no CO-RE). Objects with relocations are still gated
  (signature + scan + policy) but `--load` returns `LoadError::Unsupported`.
- No attachment, no pin, no map freeze. An in-kernel LSM (Hornet) or the
  kernel's own BPF signing is required for a privileged attacker who can call
  `bpf()` directly, skipping this userspace tool.
- Helper ids are the stable `enum bpf_func_id` numbers; names are cosmetic.

## Build / regenerate fixtures

```bash
# needs clang -target bpf
./gen/build-objs.sh
cargo run --bin gen-corpus
```

License: Apache-2.0.
