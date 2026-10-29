/* Minimal helper declarations (same pattern as libbpf bpf_helper_defs.h).
 * Helper ids come from include/uapi/linux/bpf.h (enum bpf_func_id). */
#define SEC(n) __attribute__((section(n), used))
typedef unsigned long long u64;
typedef unsigned int u32;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u32 (*bpf_get_prandom_u32)(void) = (void *)7;
static u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_write_user)(void *dst, const void *src, u32 len) = (void *)36;
static long (*bpf_override_return)(void *regs, u64 rc) = (void *)58;
static long (*bpf_send_signal)(u32 sig) = (void *)109;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
char _license[] SEC("license") = "GPL";
