#!/bin/sh
set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
default_publish_root="${HOME:?HOME must be set}/source/personal/mcp-connectors/unifi-mcp"
publish_root="${1:-$default_publish_root}"
solution="$repository_root/UnifiMcp.slnx"
project="$repository_root/src/UnifiMcp/UnifiMcp.csproj"

case "$publish_root" in
    /*) ;;
    *)
        printf 'Publish destination must be an absolute path: %s\n' "$publish_root" >&2
        exit 2
        ;;
esac

if [ "$publish_root" = "/" ]; then
    printf 'Refusing to publish to the filesystem root.\n' >&2
    exit 2
fi

current_link="$publish_root/current"
if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
    printf 'Refusing to replace non-symlink path: %s\n' "$current_link" >&2
    exit 2
fi

cd "$repository_root"

printf 'Restoring locked dependencies...\n'
dotnet restore "$solution" --locked-mode

printf 'Running Release tests...\n'
dotnet test "$solution" --configuration Release --no-restore

commit="$(git rev-parse --short=12 HEAD)"
dirty_suffix=""
if [ -n "$(git status --porcelain)" ]; then
    dirty_suffix="-dirty"
fi

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
release_name="${timestamp}-${commit}${dirty_suffix}-$$"
releases_root="$publish_root/releases"
release_path="$releases_root/$release_name"

mkdir -p "$releases_root"
staging="$(mktemp -d "$publish_root/.staging.XXXXXX")"
next_link="$publish_root/.current.$$.tmp"

cleanup() {
    rm -f "$next_link"
    if [ -d "$staging" ]; then
        rm -rf "$staging"
    fi
}
trap cleanup EXIT HUP INT TERM

printf 'Publishing Release output...\n'
dotnet publish "$project" \
    --configuration Release \
    --no-restore \
    --self-contained false \
    --output "$staging"

if [ ! -f "$staging/unifi-mcp.dll" ] || [ ! -x "$staging/unifi-mcp" ]; then
    printf 'Publish output is missing the expected DLL or executable.\n' >&2
    exit 1
fi

{
    printf 'source_commit=%s\n' "$commit"
    printf 'source_dirty=%s\n' "$([ -n "$dirty_suffix" ] && printf true || printf false)"
    printf 'published_utc=%s\n' "$timestamp"
} >"$staging/BUILD-INFO"

mv "$staging" "$release_path"
ln -s "releases/$release_name" "$next_link"
mv -f "$next_link" "$current_link"

trap - EXIT HUP INT TERM
printf 'Published UniFi MCP to %s\n' "$release_path"
printf 'Current release: %s\n' "$current_link"
printf 'Codex executable: %s/unifi-mcp\n' "$current_link"
