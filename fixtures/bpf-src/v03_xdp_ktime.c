#include "helpers.h"
SEC("xdp") int xdp_ktime(void *ctx) { return (bpf_ktime_get_ns() & 1) ? 2 : 2; }
