#!/bin/bash
# SPDX-License-Identifier: MIT
# Root + BTF kernel + liburing >= 2.3 headers + python3.
set -euo pipefail
cd "$(dirname "$0")/../.."
US=${1:-./uringscope}
mkdir -p build
${CC:-cc} -O2 -Wall -Wextra -o build/multishot-repro test/multishot/repro.c -luring
exec python3 test/multishot/check.py "$US" build/multishot-repro
