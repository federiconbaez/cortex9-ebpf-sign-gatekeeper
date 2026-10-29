#include "helpers.h"
SEC("xdp") int xdp_drop(void *ctx) { return 1; }
