#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_write(void *ctx) { u64 z = 0; bpf_probe_write_user((void *)0x1000, &z, 8); return 0; }
