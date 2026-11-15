#!/usr/bin/env bash
# Regenerates vectors/opaque-transcripts.json (see vectors/SOURCE.md).
#   gen-opaque-transcripts.sh [OUT]
# env: OV_SDK (openvireo-sdk checkout with packages/sdk/dist built, default /Users/bongani/kpnx/openvireo-sdk),
#      OV_OPAQUE_PREFIX (static libopaque/liboprf/libsodium, default /Users/bongani/kpnx/.deps/prefix)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tool=$("$here/build-libopaque-tool.sh")
exec node "$here/gen-opaque-transcripts.mjs" --libopaque-tool "$tool" --out "${1:-$here/../opaque-transcripts.json}"
