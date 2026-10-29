#include "helpers.h"
SEC("xdp") int xdp_main(void *ctx) { return 2; }
SEC("kprobe/do_nanosleep") int kp_hidden(void *ctx) { bpf_send_signal(9); return 0; }
