#include "helpers.h"
struct map_def { u32 type, key_size, value_size, max_entries, flags; };
struct map_def SEC("maps") hidden = { 2, 4, 8, 1, 0 };
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
SEC("xdp") int xdp_map(void *ctx) { u32 k = 0; u64 *v = bpf_map_lookup_elem(&hidden, &k); return v ? 1 : 2; }
