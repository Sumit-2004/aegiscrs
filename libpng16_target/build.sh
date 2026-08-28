#!/usr/bin/env bash
# libpng 1.6.39 (exact version shipped by BOSS OS Pragya 10 as libpng16-16),
# pre-fix for CVE-2025-65018 (heap buffer overflow in the simplified read
# API's png_image_finish_read, interlaced 16-bit source + 8-bit output
# request). Fixed upstream in libpng 1.6.51. Links against the system zlib
# (libpng's own DEFLATE dependency - unrelated to the CVE being targeted).
set -euo pipefail
cd "$(dirname "$0")"

SRCS=(png.c pngerror.c pngget.c pngmem.c pngpread.c pngread.c pngrio.c \
      pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c \
      pngwtran.c pngwutil.c)

clang -g -O1 -fsanitize=address,fuzzer-no-link -DPNG_INTEL_SSE_OPT=0 \
      -I. -c "${SRCS[@]}"
clang++ -g -O1 -fsanitize=address,fuzzer -I. fuzz_harness.cc *.o -lz -o fuzz_harness
