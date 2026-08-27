#!/usr/bin/env bash
# Minimal direct build: skips autotools/oss-fuzz's docker infra entirely.
# Uses the prebuilt generic config header (no hardware SIMD, no configure step)
# and compiles the harness + libpng sources straight with clang, ASan+libFuzzer.
set -euo pipefail
cd "$(dirname "$0")"

cp -f scripts/pnglibconf.h.prebuilt pnglibconf.h

SRCS=(png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c \
      pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c \
      pngwtran.c pngwutil.c)

clang++ -g -O1 -std=c++11 -fsanitize=address,fuzzer -DPNG_INTERNAL -I. \
    contrib/oss-fuzz/libpng_read_fuzzer.cc "${SRCS[@]}" \
    -lz -o fuzz_harness
