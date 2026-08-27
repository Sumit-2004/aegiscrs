#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
clang -g -O1 -fsanitize=address -o test_basic test_basic.c ../vulnerable/session.c
./test_basic
