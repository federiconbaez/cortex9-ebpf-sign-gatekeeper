#include "helpers.h"
SEC("tracepoint/sched/sched_switch") int tp_cpu(void *ctx) { return bpf_get_smp_processor_id() == 0; }
