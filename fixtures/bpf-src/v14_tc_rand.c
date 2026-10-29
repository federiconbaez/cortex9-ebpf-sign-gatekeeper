#include "helpers.h"
SEC("tc") int tc_rand(void *ctx) { return bpf_get_prandom_u32() == 0 ? 2 : 0; }
