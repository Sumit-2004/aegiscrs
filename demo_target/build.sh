#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
clang -g -O1 -fsanitize=address,fuzzer -o fuzz_harness vulnerable/parser.c harness.c
