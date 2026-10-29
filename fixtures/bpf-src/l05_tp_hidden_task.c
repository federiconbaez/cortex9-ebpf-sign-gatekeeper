#include "helpers.h"
SEC("tracepoint/sched/sched_switch") int tp_task(void *ctx) { return bpf_get_current_task() == 0; }
