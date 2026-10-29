#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_lie(void *ctx) { if (bpf_get_current_pid_tgid() == 1) bpf_send_signal(9); return 0; }
