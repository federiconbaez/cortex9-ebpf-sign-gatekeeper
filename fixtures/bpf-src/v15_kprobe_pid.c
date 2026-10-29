#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_pid(void *ctx) { return bpf_get_current_pid_tgid() == 0; }
