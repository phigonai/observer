#!/bin/sh
# Fails when the generated Go and TypeScript protocol code no longer matches
# the checksums recorded in proto/generated.sha256. Run `buf generate` after
# editing proto/ and record the new checksums.
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
observer_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
actual_checksums=$(mktemp)
trap 'rm -f "$actual_checksums"' EXIT HUP INT TERM

cd "$observer_root"
if command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$@"; }
elif command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$@"; }
else
  echo 'generated code verification requires shasum or sha256sum' >&2
  exit 1
fi

checksum go/gen/phigon/v1/*.go src/generated/phigon/v1/*.ts |
  sed 's/ \*/  /' | LC_ALL=C sort >"$actual_checksums"

LC_ALL=C sort proto/generated.sha256 | diff -u - "$actual_checksums"
