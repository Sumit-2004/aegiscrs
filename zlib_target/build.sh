#!/usr/bin/env bash
# zlib 1.2.11 (pre-CVE-2022-37434 fix), harness targets the vulnerable
# inflateGetHeader()/inflate() gzip EXTRA-field handling in inflate.c.
set -euo pipefail
cd "$(dirname "$0")"

SRCS=(adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c \
      gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c \
      zutil.c)

# zutil.c uses pre-ANSI K&R function definitions, invalid as C++ - compile the
# library as C, then link the C++ harness against the resulting objects.
clang -g -O1 -fsanitize=address,fuzzer-no-link -c "${SRCS[@]}"
clang++ -g -O1 -fsanitize=address,fuzzer -I. fuzz_harness.cc *.o -o fuzz_harness
