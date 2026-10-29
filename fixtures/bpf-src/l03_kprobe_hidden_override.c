#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_override(void *ctx) { bpf_override_return(ctx, 0); return 0; }
