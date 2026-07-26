#!/bin/sh
set -eu

version="${1:-10.4.57}"
destination="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/contracts/unifi-network.openapi.json"
temporary="$(mktemp "${TMPDIR:-/tmp}/unifi-openapi.XXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

curl --fail --location --silent --show-error \
  "https://developer.ui.com/network/v${version}/openapi.json" \
  --output "$temporary"

jq -e --arg expected "$version" \
  '.openapi and .paths and .info.version == $expected' \
  "$temporary" >/dev/null

mv "$temporary" "$destination"
printf 'Updated %s from Network API %s\n' "$destination" "$version"
