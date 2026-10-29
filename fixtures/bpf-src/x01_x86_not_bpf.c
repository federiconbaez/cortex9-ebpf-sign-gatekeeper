/* Native (non-BPF) object: must be rejected even if correctly signed. */
int not_bpf(void) { return 42; }
