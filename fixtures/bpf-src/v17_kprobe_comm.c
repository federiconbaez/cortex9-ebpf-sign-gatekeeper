#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_comm(void *ctx) { char c[16]; bpf_get_current_comm(c, sizeof(c)); return c[0] == 0; }
