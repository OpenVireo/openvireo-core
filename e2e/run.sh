#!/bin/sh
# Cross-client end-to-end tests against the local stack (README.md next to this file).
#
#   OV_E2E_SDK_DIR=../openvireo-sdk e2e/run.sh                      ov + SDK scenarios only
#   OV_E2E_SDK_DIR=… OV_E2E_IOS_DIR=… OV_E2E_DESKTOP_BUILD=… e2e/run.sh   the whole matrix
#
# Variables:
#   OV_COMPOSE_FILE       the stack's compose.yaml (default: compose.yaml next to the main openvireo-core checkout)
#   OV_E2E_SERVICES       services to start (default "auth sync": all the clients here need)
#   OV_E2E_SDK_DIR        openvireo-sdk checkout with packages/sdk/dist built (required)
#   OV_BIN                an ov binary (default: built from this checkout into e2e/target)
#   OV_E2E_IOS_DIR        openvireo-ios checkout with its vendored core built: runs its e2e suites
#   OV_E2E_IOS_DESTINATION  xcodebuild destination (default: a new iPhone 17 simulator on the newest iOS runtime,
#                         deleted afterwards: the UI tests depend on the accounts a simulator remembers from earlier runs)
#   OV_E2E_DESKTOP_BUILD  openvireo desktop CMake build dir: runs its live-server tests and its openvireo-kdbx
#   OV_E2E_OUT_DIR        logs and results (default: a new temporary directory)
#   OV_E2E_ONLY           comma-separated cross-client scenarios (e.g. 2,5)
#   OV_E2E_STRICT=1       known failures fail the run too
#   OV_E2E_FRESH=1        a clean stack: stops the everyday stack (its data stays), runs a throwaway compose project
#                         with new volumes on the same ports, deletes it afterwards and starts the everyday stack again
# Exit status: 0 when nothing failed (known failures aside), else 1.
set -eu
E2E=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$E2E")
ISSUER=http://localhost:8000

if [ -z "${OV_COMPOSE_FILE:-}" ]; then
  common=$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)
  for candidate in "${common:+$(dirname "$(dirname "$common")")/compose.yaml}" "$(dirname "$ROOT")/compose.yaml"; do
    [ -n "$candidate" ] && [ -f "$candidate" ] && { OV_COMPOSE_FILE=$candidate; break; }
  done
fi
[ -n "${OV_COMPOSE_FILE:-}" ] && [ -f "$OV_COMPOSE_FILE" ] || { echo "compose.yaml not found; set OV_COMPOSE_FILE" >&2; exit 2; }
[ -n "${OV_E2E_SDK_DIR:-}" ] && [ -f "$OV_E2E_SDK_DIR/packages/sdk/dist/index.js" ] || {
  echo "set OV_E2E_SDK_DIR to an openvireo-sdk checkout with the SDK built (npm ci && npm run build -w packages/sdk)" >&2
  exit 2
}
OUT=${OV_E2E_OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/ov-e2e.XXXXXX")}
mkdir -p "$OUT"
rm -f "$OUT"/*.status "$OUT"/cross-client.json
compose() { docker compose -f "$OV_COMPOSE_FILE" "$@"; }
echo "logs and results: $OUT"

RESETTER=
SIMULATOR=
STOPPED=
FRESH_PROJECT=
cleanup() {
  [ -z "$RESETTER" ] || kill "$RESETTER" 2>/dev/null || :
  if [ -n "$SIMULATOR" ]; then
    xcrun simctl shutdown "$SIMULATOR" >/dev/null 2>&1 || :
    xcrun simctl delete "$SIMULATOR" >/dev/null 2>&1 || :
  fi
  if [ -n "$FRESH_PROJECT" ]; then
    echo "deleting the throwaway stack $FRESH_PROJECT"
    COMPOSE_PROJECT_NAME=$FRESH_PROJECT compose down -v --remove-orphans >>"$OUT/compose.log" 2>&1 || :
  fi
  if [ -n "$STOPPED" ]; then
    echo "starting the everyday stack again: $STOPPED"
    # shellcheck disable=SC2086
    env -u COMPOSE_PROJECT_NAME docker compose -f "$OV_COMPOSE_FILE" start $STOPPED >>"$OUT/compose.log" 2>&1 || :
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ "${OV_E2E_FRESH:-}" = 1 ]; then
  # the project named in .env (or the folder name); the throwaway one takes its ports for the run
  STOPPED=$(env -u COMPOSE_PROJECT_NAME docker compose -f "$OV_COMPOSE_FILE" ps --services --status running | tr '\n' ' ')
  if [ -n "$STOPPED" ]; then
    echo "stopping the everyday stack for the run (its volumes stay): $STOPPED"
    env -u COMPOSE_PROJECT_NAME docker compose -f "$OV_COMPOSE_FILE" stop >"$OUT/compose.log" 2>&1
  fi
  FRESH_PROJECT=openvireo-e2e-$$
  export COMPOSE_PROJECT_NAME=$FRESH_PROJECT   # also reaches the iOS test-e2e.sh's compose calls
fi

# 1. the stack
echo "starting the stack ($OV_COMPOSE_FILE: ${OV_E2E_SERVICES:-auth sync})"
# shellcheck disable=SC2086
compose up -d --wait ${OV_E2E_SERVICES:-auth sync} >>"$OUT/compose.log" 2>&1 || { cat "$OUT/compose.log" >&2; exit 1; }
i=0
until curl -fsS -m 3 "$ISSUER/.well-known/openvireo-configuration" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 60 ] || { echo "$ISSUER did not come up" >&2; exit 1; }; sleep 1
done
curl -sS -m 3 -o /dev/null http://localhost:8787/ || { echo "the sync server on :8787 does not answer" >&2; exit 1; }

# 2. rate limits: the auth server allows 5 registrations a minute per IP and the runs register many accounts,
#    so the local stack's counters are cleared now and every two seconds while the tests run (as the iOS
#    test-e2e.sh does). Only ever against the local stack.
reset_limits() { compose exec -T redis sh -c "redis-cli --scan --pattern 'LIMITS*' | xargs -r redis-cli del" >/dev/null 2>&1 || :; }
reset_limits
(while :; do reset_limits; sleep 2; done) &
RESETTER=$!

# 3. ov
if [ -z "${OV_BIN:-}" ]; then
  echo "building ov"
  (cd "$ROOT" && cargo build --quiet --locked -p ov --target-dir "$E2E/target") >"$OUT/ov-build.log" 2>&1 || {
    cat "$OUT/ov-build.log" >&2; exit 1; }
  OV_BIN=$E2E/target/debug/ov
fi
"$OV_BIN" version

KDBX_CLI=
if [ -n "${OV_E2E_DESKTOP_BUILD:-}" ] && [ -x "$OV_E2E_DESKTOP_BUILD/src/cli/openvireo-kdbx" ]; then
  KDBX_CLI=$OV_E2E_DESKTOP_BUILD/src/cli/openvireo-kdbx
fi

# 4. ov + SDK scenarios
status=0
echo; echo "== ov + SDK scenarios"
OV_BIN=$OV_BIN OV_E2E_ISSUER=$ISSUER OV_E2E_KDBX_CLI=$KDBX_CLI OV_E2E_OUT=$OUT/cross-client.json \
  node "$E2E/cross-client.mjs" 2>&1 | tee "$OUT/cross-client.log"
# tee hides node's status: the JSON says what failed, and matrix.mjs turns it into the exit status below
[ -f "$OUT/cross-client.json" ] || { echo "cross-client.mjs wrote no results" >&2; status=1; }

# 5. iOS: its own e2e suites (each bundle on its own so one failure doesn't hide the rest)
if [ -n "${OV_E2E_IOS_DIR:-}" ]; then
  echo; echo "== iOS e2e suites ($OV_E2E_IOS_DIR)"
  destination=${OV_E2E_IOS_DESTINATION:-}
  if [ -z "$destination" ]; then
    runtime=$(xcrun simctl list runtimes available | grep -oE 'com\.apple\.CoreSimulator\.SimRuntime\.iOS-[0-9-]+' | sort -t- -k2,2n -k3,3n | tail -1)
    SIMULATOR=$(xcrun simctl create "ov-e2e-$$" com.apple.CoreSimulator.SimDeviceType.iPhone-17 "$runtime")
    destination="id=$SIMULATOR"
    echo "a new simulator for the run: iPhone 17, $runtime ($SIMULATOR)"
  fi
  for bundle in OpenVireoCoreTests/EndToEndTests OpenVireoCoreTests/AccountEndToEndTests OpenVireoCoreTests/OrgEndToEndTests \
    OpenVireoCoreTests/AccountSettingsEndToEndTests OpenVireoKitTests/AccountStoreTests OpenVireoKitTests/SelfHostedEndToEndTests \
    OpenVireoUITests/AccountFlowUITests; do
    name=$(echo "$bundle" | tr / .)
    printf '%s ... ' "$bundle"
    if OV_COMPOSE_FILE=$OV_COMPOSE_FILE OV_E2E_BUNDLES=$bundle \
      DESTINATION=$destination \
      "$OV_E2E_IOS_DIR/scripts/test-e2e.sh" -derivedDataPath "$OUT/ios-derived-data" >"$OUT/ios-$name.log" 2>&1; then
      echo pass; echo pass >"$OUT/ios-$name.status"
    else
      echo "FAIL (log: $OUT/ios-$name.log)"; echo fail >"$OUT/ios-$name.status"
    fi
  done
fi

# 6. desktop: its live-server tests (self-hosted sync against this sync server). testPlatformTokenStore is never
#    run (it is the one test that may use the system keychain), and HOME is a scratch folder.
if [ -n "${OV_E2E_DESKTOP_BUILD:-}" ]; then
  echo; echo "== desktop live-server tests ($OV_E2E_DESKTOP_BUILD)"
  token=$(compose run --rm -T sync users add "e2e-desktop-$(date +%s)" laptop 2>/dev/null | awk 'NF == 1 && length($1) > 20 { print $1 }' | tail -1)
  [ -n "$token" ] || { echo "could not get a sync server token" >&2; exit 1; }
  dhome=$(mktemp -d "$OUT/desktop-home.XXXXXX")
  run_desktop() { # name binary [functions…]
    n=$1; shift
    printf '%s ... ' "$n"
    if HOME=$dhome QT_QPA_PLATFORM=offscreen OPENVIREO_SYNC_SERVER_URL=http://127.0.0.1:8787 OPENVIREO_SYNC_SERVER_TOKEN=$token \
      "$@" >"$OUT/desktop-$n.log" 2>&1 && ! grep -q '^SKIP' "$OUT/desktop-$n.log"; then
      echo "pass ($(grep '^Totals' "$OUT/desktop-$n.log"))"; echo pass >"$OUT/desktop-$n.status"
    else
      echo "FAIL (log: $OUT/desktop-$n.log)"; echo fail >"$OUT/desktop-$n.status"
    fi
  }
  t=$OV_E2E_DESKTOP_BUILD/tests
  run_desktop testremotesyncserver "$t/testremotesyncserver" testTestsNeverGetTheSystemStore testSyncServerCycle \
    testSyncServerRejectsBadToken testSyncEngineTwoDevices testHistoryAndEvents testRecognisesPairingCodes \
    testExplainsAVaultOverItsQuota testPairsAnotherDevice
  gui=$t/gui/testguiautosync; [ -x "$gui" ] || gui=$t/testguiautosync
  run_desktop testguiautosync "$gui"
  unset token
fi

# 7. the matrix
echo
node "$E2E/matrix.mjs" "$OUT" | tee "$OUT/matrix.txt"
node "$E2E/matrix.mjs" --check "$OUT" || status=1
exit $status
