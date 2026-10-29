#include "helpers.h"
SEC("tc") int tc_cpu(void *ctx) { return bpf_get_smp_processor_id() > 100000 ? 2 : 0; }
