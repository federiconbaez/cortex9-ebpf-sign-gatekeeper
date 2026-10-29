#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_claims_sock(void *ctx) { return 0; }
