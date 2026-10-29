#include "helpers.h"
SEC("xdp") int xdp_claims_sock(void *ctx) { return 2; }
