#!/usr/bin/env bash
# SHA256SUMS handling for the release assets.
#   checksums.sh generate <dir> <file>...   writes <dir>/SHA256SUMS for exactly the given files
#   checksums.sh verify <dir>               recomputes every digest and compares
# Digests are recomputed with sha256_file (sha256sum or shasum), so verification does not depend on
# `sha256sum -c` and works on macOS too.
set -euo pipefail
umask 077
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

usage() { die "usage: checksums.sh generate <dir> <file>... | verify <dir>"; }

[[ $# -ge 2 ]] || usage
cmd="$1" dir="$2"
shift 2
[[ -d "$dir" ]] || die "not a directory: $dir"

# list_dir_files <dir>: basenames of all entries, one per line, sorted, excluding SHA256SUMS.
list_dir_files() {
  find "$1" -mindepth 1 -maxdepth 1 ! -name SHA256SUMS -exec basename {} \; | LC_ALL=C sort
}

case "$cmd" in
  generate)
    [[ $# -ge 1 ]] || usage
    given=""
    for f in "$@"; do
      [[ -f "$f" ]] || die "not a file: $f"
      [[ "$(cd "$(dirname "$f")" && pwd)" == "$(cd "$dir" && pwd)" ]] || die "$f is not inside $dir"
      given="${given}$(basename "$f")"$'\n'
    done
    given=$(printf '%s' "$given" | LC_ALL=C sort)
    present=$(list_dir_files "$dir")
    [[ "$given" == "$present" ]] ||
      die "directory $dir does not contain exactly the given files (extra or missing entries would be uploaded without a checksum)"
    out="$dir/SHA256SUMS"
    : >"$out"
    while IFS= read -r name; do
      printf '%s  %s\n' "$(sha256_file "$dir/$name")" "$name" >>"$out"
    done <<<"$given"
    log "wrote $out"
    ;;
  verify)
    [[ $# -eq 0 ]] || usage
    sums="$dir/SHA256SUMS"
    [[ -f "$sums" ]] || die "missing $sums"
    listed=""
    line_re='^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$'
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ $line_re ]] || die "malformed SHA256SUMS line: $line"
      want="${BASH_REMATCH[1]}" name="${BASH_REMATCH[2]}"
      [[ -f "$dir/$name" ]] || die "listed file is missing: $name"
      got=$(sha256_file "$dir/$name")
      [[ "$got" == "$want" ]] || die "checksum mismatch for $name"
      listed="${listed}${name}"$'\n'
    done <"$sums"
    listed=$(printf '%s' "$listed" | LC_ALL=C sort)
    present=$(list_dir_files "$dir")
    [[ "$listed" == "$present" ]] || die "files in $dir and entries in SHA256SUMS differ"
    log "checksums OK ($(printf '%s\n' "$listed" | grep -c .) files)"
    ;;
  *)
    usage
    ;;
esac
