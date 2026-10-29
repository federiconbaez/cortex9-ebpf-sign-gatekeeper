use ebpf_sign_gatekeeper::corpus::{fixtures_root, run_corpus};
use ebpf_sign_gatekeeper::gate::{check, gate_and_load, Bundle, Outcome};
use ebpf_sign_gatekeeper::loader::RecordingLoader;
use ebpf_sign_gatekeeper::sig::TrustStore;

#[test]
fn acceptance_criteria() {
    let root = fixtures_root();
    let r = run_corpus(&root).expect("corpus");
    assert!(r.total >= 38, "need ≥38 fixtures (got {})", r.total);
    assert_eq!(r.unauthorized_loads, 0, "unauthorized loads must be 0");
    assert_eq!(
        r.valid_allowed, r.valid_total,
        "every valid signed fixture must pass"
    );
    assert!(r.valid_total >= 20);
    assert_eq!(
        r.lying_caught, r.lying_total,
        "every lying-manifest fixture must be denied"
    );
    assert!(r.lying_total >= 10);
    assert_eq!(r.failed, 0, "report={r:?}");
}

#[test]
fn denied_never_reaches_loader() {
    let root = fixtures_root();
    let ts = TrustStore::load_dir(&root.join("keys")).unwrap();
    let mut loader = RecordingLoader::default();
    for id in [
        "u01_unsigned",
        "t01_object_bitflip",
        "l01_kprobe_hidden_probe_read",
        "l08_xdp_hidden_second_prog",
        "x01_x86_not_bpf",
    ] {
        let b = Bundle::read_dir(&root.join("cases").join(id)).unwrap();
        match gate_and_load(&b, &ts, &mut loader) {
            Outcome::Denied(_) => {}
            other => panic!("{id}: expected Denied, got {other:?}"),
        }
    }
    assert!(
        loader.calls.is_empty(),
        "loader was invoked on denied cases: {:?}",
        loader.calls
    );
}

#[test]
fn valid_reaches_loader_exactly_once_each() {
    let root = fixtures_root();
    let ts = TrustStore::load_dir(&root.join("keys")).unwrap();
    let mut loader = RecordingLoader::default();
    let index = ebpf_sign_gatekeeper::corpus::load_index(&root).unwrap();
    for c in index.iter().filter(|c| c.kind == "valid") {
        let b = Bundle::read_dir(&root.join("cases").join(&c.id)).unwrap();
        match gate_and_load(&b, &ts, &mut loader) {
            Outcome::Loaded(_) => {}
            other => panic!("{}: expected Loaded, got {other:?}", c.id),
        }
    }
    assert_eq!(loader.calls.len(), 20);
}

#[test]
fn check_alone_does_not_call_bpf() {
    // Smoke: even the first valid fixture's check() must succeed without CAP_BPF.
    let root = fixtures_root();
    let ts = TrustStore::load_dir(&root.join("keys")).unwrap();
    let b = Bundle::read_dir(&root.join("cases/v01_xdp_pass")).unwrap();
    assert!(check(&b, &ts).is_ok());
}
