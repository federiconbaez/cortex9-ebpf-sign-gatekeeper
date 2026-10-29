#include "helpers.h"
SEC("xdp") int xdp_cpu(void *ctx) { return bpf_get_smp_processor_id() > 4096 ? 1 : 2; }
