#include "helpers.h"
SEC("socket") int sock_rand(void *ctx) { return bpf_get_prandom_u32() & 0xff; }
