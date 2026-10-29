//! Names for the helper ids used in reports (subset of `enum bpf_func_id`,
//! include/uapi/linux/bpf.h). Unknown ids are still checked, just unnamed.

pub fn helper_name(id: i32) -> &'static str {
    match id {
        1 => "bpf_map_lookup_elem",
        2 => "bpf_map_update_elem",
        3 => "bpf_map_delete_elem",
        4 => "bpf_probe_read",
        5 => "bpf_ktime_get_ns",
        6 => "bpf_trace_printk",
        7 => "bpf_get_prandom_u32",
        8 => "bpf_get_smp_processor_id",
        14 => "bpf_get_current_pid_tgid",
        15 => "bpf_get_current_uid_gid",
        16 => "bpf_get_current_comm",
        23 => "bpf_redirect",
        35 => "bpf_get_current_task",
        36 => "bpf_probe_write_user",
        58 => "bpf_override_return",
        109 => "bpf_send_signal",
        112 => "bpf_probe_read_user",
        113 => "bpf_probe_read_kernel",
        _ => "unknown",
    }
}
