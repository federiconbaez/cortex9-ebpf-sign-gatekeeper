#include "helpers.h"
SEC("socket") int sock_zero(void *ctx) { return 0; }
