#include "helpers.h"
SEC("xdp") int xdp_rand(void *ctx) { return bpf_get_prandom_u32() % 100 == 0 ? 1 : 2; }
