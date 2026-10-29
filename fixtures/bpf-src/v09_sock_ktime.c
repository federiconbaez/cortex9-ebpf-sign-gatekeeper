#include "helpers.h"
SEC("socket") int sock_ktime(void *ctx) { return bpf_ktime_get_ns() ? 0 : 0; }
