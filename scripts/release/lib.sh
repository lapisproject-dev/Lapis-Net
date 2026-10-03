#!/usr/bin/env bash
# Shared helpers for the release scripts. Source it, do not execute it:
#   . "$(dirname "$0")/lib.sh"
#
# Kept compatible with Bash 3.2 (macOS): no mapfile/readarray, no associative arrays,
# no ${x,,}, no `wait -n`, no `sort -V`, no GNU-only flags.

umask 077

# Only digits and dots, three components of 1-6 digits each (keeps the arithmetic in semver_gt far
# away from overflow), leading "v". Anything else is rejected.
TAG_REGEX='^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$'

log() {
  printf '[release] %s\n' "$*" >&2
}

# Prints the message and terminates the *current* shell (inside $(...) that is the subshell, so a
# caller that captures output must still propagate the failure, which `set -e` does for plain
# assignments). Newlines and carriage returns are flattened so an attacker-controlled value (a tag
# name) can never start a new workflow command line.
die() {
  local msg="$*"
  msg=${msg//$'\n'/ }
  msg=${msg//$'\r'/ }
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::error::%s\n' "$msg" >&2
  else
    printf '[release] ERROR: %s\n' "$msg" >&2
  fi
  exit 1
}

# is_valid_tag <tag>: vX.Y.Z only, at most 32 characters, no line breaks.
is_valid_tag() {
  local t="${1-}"
  [[ ${#t} -ge 1 && ${#t} -le 32 ]] || return 1
  case "$t" in
    *$'\n'* | *$'\r'*) return 1 ;;
  esac
  [[ "$t" =~ $TAG_REGEX ]]
}

# project_version_from <treeish> [file]: the project version declared in build.gradle.kts at that
# commit. The version is a hard-coded string, not derived from the git tag (see docs/releasing.adoc).
# Exactly one `version = "X.Y.Z"` line must exist; zero or several is an error, never a guess.
project_version_from() {
  local treeish="$1" file="${2:-build.gradle.kts}" content matches count version
  content=$(git show "${treeish}:${file}") || die "cannot read ${file} at ${treeish}"
  matches=$(printf '%s\n' "$content" |
    sed -nE 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p')
  count=$(printf '%s\n' "$matches" | grep -c . || true)
  if [[ "$count" -ne 1 ]]; then
    die "expected exactly one 'version = \"...\"' line in ${file} at ${treeish}, found ${count}"
  fi
  version="$matches"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version '${version}' in ${file} is not X.Y.Z"
  printf '%s\n' "$version"
}

# sha256_file <file>: prints the lowercase hex digest. SHA256_TOOL=sha256sum|shasum forces a tool
# (used by the offline tests).
sha256_file() {
  local f="$1" tool="${SHA256_TOOL:-}" out hex
  case "$f" in
    -*) f="./$f" ;;
  esac
  if [[ -z "$tool" ]]; then
    if command -v sha256sum >/dev/null 2>&1; then
      tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
      tool=shasum
    else
      die "neither sha256sum nor shasum is available"
    fi
  fi
  case "$tool" in
    sha256sum) out=$(sha256sum "$f") || die "sha256sum failed for $f" ;;
    shasum) out=$(shasum -a 256 "$f") || die "shasum failed for $f" ;;
    *) die "unknown SHA256_TOOL '$tool'" ;;
  esac
  hex=${out%% *}
  [[ "$hex" =~ ^[0-9a-f]{64}$ ]] || die "unexpected digest output for $f"
  printf '%s\n' "$hex"
}

# semver_gt <a> <b>: success if a > b. Numeric X.Y.Z comparison, optional leading "v".
semver_gt() {
  local a="${1#v}" b="${2#v}" a1 a2 a3 b1 b2 b3
  [[ "v$a" =~ $TAG_REGEX && "v$b" =~ $TAG_REGEX ]] ||
    die "semver_gt: not X.Y.Z: '$a' / '$b'"
  IFS=. read -r a1 a2 a3 <<<"$a"
  IFS=. read -r b1 b2 b3 <<<"$b"
  a1=$((10#$a1)) a2=$((10#$a2)) a3=$((10#$a3))
  b1=$((10#$b1)) b2=$((10#$b2)) b3=$((10#$b3))
  if ((a1 != b1)); then ((a1 > b1)); return; fi
  if ((a2 != b2)); then ((a2 > b2)); return; fi
  ((a3 > b3))
}

# set_output <key> <value>: GitHub Actions step output, or stdout when run by hand.
set_output() {
  local key="$1" value="$2"
  [[ "$key" =~ ^[a-z_]+$ ]] || die "set_output: bad key '$key'"
  case "$value" in
    *$'\n'* | *$'\r'*) die "set_output: value for '$key' contains a line break" ;;
  esac
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$key" "$value" >>"$GITHUB_OUTPUT"
  else
    printf '%s=%s\n' "$key" "$value"
  fi
}
