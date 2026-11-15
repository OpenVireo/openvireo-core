#!/usr/bin/env bash
# Builds libopaque-transcript (a deterministic libopaque driver) against static libopaque, liboprf and
# libsodium, as built by openvireo's .github/scripts/build-opaque.sh (libsodium 1.0.20, liboprf f925b87,
# libopaque 6e9ac92).
#   build-libopaque-tool.sh [OUT]     env OV_OPAQUE_PREFIX (default /Users/bongani/kpnx/.deps/prefix)
# OUT defaults to target/vector-tools/libopaque-transcript in the workspace. Prints the binary's path.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
prefix=${OV_OPAQUE_PREFIX:-/Users/bongani/kpnx/.deps/prefix}
out=${1:-"$here/../../target/vector-tools/libopaque-transcript"}
mkdir -p "$(dirname "$out")"
for lib in libopaque.a liboprf.a libsodium.a; do
  [[ -f "$prefix/lib/$lib" ]] || { echo "missing $prefix/lib/$lib (run openvireo/.github/scripts/build-opaque.sh $prefix)" >&2; exit 1; }
done
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -I"$prefix/include" "$here/libopaque-transcript.c" \
  "$prefix/lib/libopaque.a" "$prefix/lib/liboprf.a" "$prefix/lib/libsodium.a" -o "$out"
echo "$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
