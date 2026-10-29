#include "helpers.h"
SEC("xdp") int xdp_two(void *ctx) { u64 t = bpf_ktime_get_ns(); u32 r = bpf_get_prandom_u32(); return (t ^ r) == 7 ? 1 : 2; }
