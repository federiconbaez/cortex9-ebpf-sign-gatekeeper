#include "helpers.h"
static __attribute__((noinline)) int helper_sub(int x) { bpf_send_signal(9); return x; }
SEC("xdp") int xdp_sub(void *ctx) { return helper_sub(2); }
