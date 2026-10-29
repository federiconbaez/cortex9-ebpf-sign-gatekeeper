#include "helpers.h"
SEC("xdp") int xdp_pass(void *ctx) { return 2; }
