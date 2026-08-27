#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
clang -g -O1 -fsanitize=address -o /tmp/aegiscrs_test_basic tests/test_basic.c vulnerable/parser.c
/tmp/aegiscrs_test_basic
echo "test_basic: OK"
