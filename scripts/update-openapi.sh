#!/bin/sh
set -eu

version="${1:-10.5.67}"
source="${2:-https://developer.ui.com/network/v${version}/openapi.json}"
destination="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/contracts/unifi-network.openapi.json"
temporary="$(mktemp "${TMPDIR:-/tmp}/unifi-openapi.XXXXXX")"
normalized="$(mktemp "${TMPDIR:-/tmp}/unifi-openapi-normalized.XXXXXX")"
ordered="$(mktemp "${TMPDIR:-/tmp}/unifi-openapi-ordered.XXXXXX")"
trap 'rm -f "$temporary" "$normalized" "$ordered"' EXIT HUP INT TERM

case "$source" in
  https://*)
    curl --fail --location --silent --show-error "$source" --output "$temporary"
    ;;
  *)
    cp "$source" "$temporary"
    ;;
esac

jq -e --arg expected "$version" \
  '.openapi and .paths and .info.version == $expected' \
  "$temporary" >/dev/null

jq '
  .servers = [
    {
      "url": "https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration",
      "description": "UniFi API Cloud Connector",
      "variables": {
        "consoleId": {
          "default": "942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999",
          "description": "ID of the console to proxy requests to"
        }
      }
    },
    {
      "url": "https://{consoleIP}/proxy/network/integration",
      "description": "Local Console",
      "variables": {
        "consoleIP": {
          "default": "192.168.0.1",
          "description": "IP address of the console on the local network"
        }
      }
    }
  ]
' "$temporary" >"$normalized"

if [ -f "$destination" ]; then
  jq --slurpfile template "$destination" '
    def align($reference):
      if type == "object" and ($reference | type) == "object" then
        . as $source |
        reduce (
          (($reference | keys_unsorted) +
            (($source | keys_unsorted) - ($reference | keys_unsorted)))[]
        ) as $key
          ({};
            if $source | has($key) then
              .[$key] = ($source[$key] | align($reference[$key]))
            else
              .
            end)
      elif type == "array" and ($reference | type) == "array" then
        . as $source |
        [range(0; $source | length) as $index |
          $source[$index] | align($reference[$index])]
      else
        .
      end;
    align($template[0])
  ' "$normalized" >"$ordered"
else
  cp "$normalized" "$ordered"
fi

mv "$ordered" "$destination"
printf 'Updated %s from Network API %s using %s\n' "$destination" "$version" "$source"
