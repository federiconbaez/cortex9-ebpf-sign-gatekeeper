#include "helpers.h"
SEC("tracepoint/syscalls/sys_enter_nanosleep") int tp_pid(void *ctx) { return (bpf_get_current_pid_tgid() >> 32) == 1; }
