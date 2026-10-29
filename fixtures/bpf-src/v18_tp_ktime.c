#include "helpers.h"
SEC("tracepoint/syscalls/sys_enter_nanosleep") int tp_ktime(void *ctx) { return bpf_ktime_get_ns() == 0; }
