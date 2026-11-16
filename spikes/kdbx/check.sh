#!/usr/bin/env bash
# W1-K1 spike: for each test file, rewrite it with keepass-rs, then compare what KeePassXC
# (openvireo-cli, the renamed keepassxc-cli) sees in the original and in the rewrite.
#
#   spikes/kdbx/check.sh [path/to/openvireo-cli]
#
# Output per file in out/<name>.{summary,orig.xml,rt.xml,diff,raw-orig.xml,raw-rt.xml}.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cli="${1:-$repo/../../openvireo/build/src/cli/openvireo-cli}"
spike="$here/target/release/kdbx-spike"
out="$here/out"
mkdir -p "$out"

vault_hex=$(python3 -c "import json;print(json.load(open('$repo/vectors/test-vectors.json'))['vault_kdbx']['vault_key_hex'])")
python3 -c "import sys;open('$out/vault.key','wb').write(bytes.fromhex('$vault_hex'))"

# name|path|cred
files=(
  "vault-fixture|$repo/vectors/vault-fixture.kdbx|keyhex:$vault_hex"
  "desktop-kdbx31|$repo/vectors/kdbx/desktop-kdbx31.kdbx|pw:desktop pw ✓"
  "desktop-kdbx4-argon2d|$repo/vectors/kdbx/desktop-kdbx4-argon2d.kdbx|pw:desktop pw ✓"
  "kdbxweb-vault|$here/files/kdbxweb-vault.kdbx|keyhex:$vault_hex"
  "kdbxweb-unknown|$here/files/kdbxweb-unknown.kdbx|pw:spike pw"
  "kdbxweb-unknown-leaf|$here/files/kdbxweb-unknown-leaf.kdbx|pw:spike pw"
  "ios-interop|$here/files/ios-interop.kdbx|pw:desktop pw ✓"
  "ios-passkey|$here/files/ios-passkey.kdbx|pw:interop"
)

export_xml() { # path cred
  if [[ "$2" == keyhex:* ]]; then
    "$cli" export -q --no-password -k "$out/vault.key" "$1"
  else
    printf '%s\n' "${2#pw:}" | "$cli" export -q "$1"
  fi
}

for spec in "${files[@]}"; do
  IFS='|' read -r name path cred <<<"$spec"
  echo "=== $name"
  if [[ ! -f "$path" ]]; then echo "missing: $path"; continue; fi
  if ! "$spike" roundtrip "$path" "$out/$name.rt.kdbx" "$cred" >"$out/$name.summary" 2>&1; then
    echo "keepass-rs: $(tail -1 "$out/$name.summary")"
    continue
  fi
  tail -1 "$out/$name.summary"
  "$spike" xml "$path" "$cred" >"$out/$name.raw-orig.xml" 2>&1
  "$spike" xml "$out/$name.rt.kdbx" "$cred" >"$out/$name.raw-rt.xml" 2>&1
  export_xml "$path" "$cred" >"$out/$name.orig.xml" 2>"$out/$name.orig.err"
  if export_xml "$out/$name.rt.kdbx" "$cred" >"$out/$name.rt.xml" 2>"$out/$name.rt.err"; then
    echo "keepassxc-cli opens rewrite: yes ($(grep -c '<Entry>' "$out/$name.rt.xml") <Entry> elements, original $(grep -c '<Entry>' "$out/$name.orig.xml"))"
  else
    echo "keepassxc-cli opens rewrite: NO: $(cat "$out/$name.rt.err")"
  fi
  diff "$out/$name.orig.xml" "$out/$name.rt.xml" >"$out/$name.diff"
  echo "KeePassXC-visible diff lines (orig vs rewrite): $(grep -c '^[<>]' "$out/$name.diff")"
  echo "unknown elements (Zz*) in raw XML: original $(grep -o '<Zz[A-Za-z]*' "$out/$name.raw-orig.xml" | wc -l | tr -d ' '), rewrite $(grep -o '<Zz[A-Za-z]*' "$out/$name.raw-rt.xml" | wc -l | tr -d ' ')"
done
