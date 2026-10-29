#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_read(void *ctx) { u64 v = 0; bpf_probe_read_kernel(&v, 8, (void *)0); return v != 0; }
