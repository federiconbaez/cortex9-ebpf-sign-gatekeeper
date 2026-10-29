#include "helpers.h"
SEC("kprobe/do_nanosleep") int kp_uid(void *ctx) { return bpf_get_current_uid_gid() == 0; }
