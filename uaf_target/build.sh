#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
clang -g -O1 -fsanitize=address,fuzzer -o fuzz_harness vulnerable/session.c harness.c
