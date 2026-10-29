#!/usr/bin/env bash
# Rebuild fixtures/bpf-obj/*.o from fixtures/bpf-src/*.c.
# The committed .o are the ones signed by gen-corpus; rebuilding with another
# clang version may change bytes (then re-run gen-corpus).
set -euo pipefail
cd "$(dirname "$0")/../fixtures/bpf-src"
for f in [vl]*.c; do clang -O2 -target bpf -c "$f" -o "../bpf-obj/${f%.c}.o"; done
clang -O2 -target x86_64-linux-gnu -c x01_x86_not_bpf.c -o ../bpf-obj/x01_x86_not_bpf.o
head -c 512 /dev/zero | tr '\0' 'Z' > ../bpf-obj/x02_garbage.o
clang --version | head -1 > ../bpf-obj/CLANG_VERSION
