#!/usr/bin/env bash
# Smoke test for the two distribution ZIPs:
#   smoke-test-dist.sh --cli-zip P --browser-zip P [--cli-timeout 180] [--browser-timeout 120]
#
# For each ZIP: integrity (unzip -t), layout (one root directory lapis-net-<mod>-<version>/ with an
# executable bin/lapis-net-<mod> and lib/*.jar), then it actually runs the unpacked distribution.
#   CLI      runs the multi-node demo (it ends by itself after roughly 10 s) and must exit 0 and print
#            the success markers.
#   Browser  starts the node, checks /, /api/identity and /api/peers over HTTP, stops it with SIGTERM
#            (exit 143 is the expected, successful outcome), checks that the encrypted identity file
#            exists with mode 0600 and that the passphrase never appears in the log.
#
# Every run uses a fresh LAPISNET_HOME inside a private temp directory, so the real identity under
# ~/.lapisnet is never touched. The browser port (7878) is fixed in the application; if something
# already listens there the script aborts before it starts anything.
# KEEP_SMOKE_DIR=1 keeps the temp directory for debugging (its log files contain no passphrase if
# the check passed, but it is still a debugging aid, never a CI default).
set -euo pipefail
umask 077
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

cli_zip="" browser_zip="" cli_timeout=180 browser_timeout=120
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cli-zip) cli_zip="${2-}"; shift 2 ;;
    --browser-zip) browser_zip="${2-}"; shift 2 ;;
    --cli-timeout) cli_timeout="${2-}"; shift 2 ;;
    --browser-timeout) browser_timeout="${2-}"; shift 2 ;;
    *) die "unknown argument '$1'" ;;
  esac
done
[[ -n "$cli_zip" && -n "$browser_zip" ]] || die "--cli-zip and --browser-zip are required"
[[ "$cli_timeout" =~ ^[0-9]+$ && "$browser_timeout" =~ ^[0-9]+$ ]] || die "timeouts must be whole seconds"
[[ -f "$cli_zip" ]] || die "not a file: $cli_zip"
[[ -f "$browser_zip" ]] || die "not a file: $browser_zip"

BROWSER_PORT=7878
PIDS=""
WORK=""

# terminate_pid <pid> <grace-seconds>: TERM, then KILL after the grace period, then reap.
terminate_pid() {
  local pid="$1" grace="$2" waited=0
  kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null || true; return 0; }
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    if ((waited >= grace)); then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  trap - EXIT INT TERM
  local p
  for p in $PIDS; do
    terminate_pid "$p" 15
  done
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    if [[ "${KEEP_SMOKE_DIR:-}" == "1" ]]; then
      log "keeping $WORK (KEEP_SMOKE_DIR=1)"
    else
      rm -rf "$WORK"
    fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# wait_deadline <pid> <seconds>: success if the process ended within the deadline.
wait_deadline() {
  local pid="$1" limit="$2" waited=0
  while kill -0 "$pid" 2>/dev/null; do
    ((waited < limit)) || return 1
    sleep 1
    waited=$((waited + 1))
  done
}

show_log() {
  log "last 200 lines of $1:"
  tail -n 200 "$1" >&2 || true
}

for tool in unzip curl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/lapisnet-smoke.XXXXXX")
chmod 700 "$WORK"

# check_and_unpack <zip> <module>: validates the archive and prints the unpacked root directory.
check_and_unpack() {
  local zip="$1" mod="$2" base version entries roots root_count root name_re
  base=$(basename "$zip")
  name_re="^lapis-net-${mod}-([0-9]+\.[0-9]+\.[0-9]+)\.zip\$"
  [[ "$base" =~ $name_re ]] ||
    die "unexpected file name '$base' (expected lapis-net-${mod}-X.Y.Z.zip)"
  version="${BASH_REMATCH[1]}"
  unzip -tq "$zip" >/dev/null 2>&1 || die "$base is corrupt (unzip -t failed)"
  entries=$(unzip -Z1 "$zip") || die "cannot list $base"
  # path traversal / absolute paths / files directly in the archive root
  if printf '%s\n' "$entries" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    die "$base contains absolute or parent-relative paths"
  fi
  if printf '%s\n' "$entries" | grep -Evq '/'; then
    die "$base has entries outside a single root directory"
  fi
  roots=$(printf '%s\n' "$entries" | sed -nE 's#^([^/]+)/.*#\1#p' | LC_ALL=C sort -u)
  root_count=$(printf '%s\n' "$roots" | grep -c . || true)
  [[ "$root_count" -eq 1 ]] || die "$base must contain exactly one root directory, found $root_count"
  root="$roots"
  [[ "$root" == "lapis-net-${mod}-${version}" ]] ||
    die "root directory '$root' does not match the file name ($base)"
  mkdir -p "$WORK/$mod"
  unzip -q "$zip" -d "$WORK/$mod" || die "cannot unpack $base"
  [[ -f "$WORK/$mod/$root/bin/lapis-net-$mod" && -x "$WORK/$mod/$root/bin/lapis-net-$mod" ]] ||
    die "$base: bin/lapis-net-$mod missing or not executable"
  [[ -n "$(find "$WORK/$mod/$root/lib" -maxdepth 1 -name '*.jar' 2>/dev/null | head -n 1)" ]] ||
    die "$base: lib/ contains no .jar"
  log "$base: archive structure OK (version $version)"
  printf '%s\n' "$WORK/$mod/$root"
}

cli_root=$(check_and_unpack "$cli_zip" cli)
browser_root=$(check_and_unpack "$browser_zip" browser)

# Port check before anything is started. Never kills a foreign process.
if (exec 3<>"/dev/tcp/127.0.0.1/$BROWSER_PORT") 2>/dev/null; then
  die "port $BROWSER_PORT busy - stop whatever listens there and re-run (the browser port is fixed)"
fi

# The distribution scripts use JAVA_HOME if set, otherwise java from PATH.
if [[ "${SMOKE_SKIP_JAVA_CHECK:-}" != "1" ]]; then
  java_bin="java"
  [[ -n "${JAVA_HOME:-}" ]] && java_bin="$JAVA_HOME/bin/java"
  command -v "$java_bin" >/dev/null 2>&1 || [[ -x "$java_bin" ]] || die "no java found (set JAVA_HOME or put JDK 25 on PATH)"
  java_major=$("$java_bin" -version 2>&1 | sed -nE 's/.*version "([0-9]+).*/\1/p' | head -n 1)
  [[ -n "$java_major" && "$java_major" -ge 25 ]] || die "JDK 25 or newer is required, found '${java_major:-unknown}'"
fi

# ---- (a) CLI ---------------------------------------------------------------------------------
log "running the CLI demo (limit ${cli_timeout}s)"
mkdir -p "$WORK/cli-home" "$WORK/cli-tmp"
cli_log="$WORK/cli.log"
LAPISNET_HOME="$WORK/cli-home" JAVA_OPTS="-Djava.io.tmpdir=$WORK/cli-tmp" \
  "$cli_root/bin/lapis-net-cli" >"$cli_log" 2>&1 </dev/null &
cli_pid=$!
PIDS="$PIDS $cli_pid"
if ! wait_deadline "$cli_pid" "$cli_timeout"; then
  show_log "$cli_log"
  die "CLI did not finish within ${cli_timeout}s"
fi
cli_rc=0
wait "$cli_pid" || cli_rc=$?
PIDS=${PIDS/ $cli_pid/}
if [[ "$cli_rc" -ne 0 ]]; then
  show_log "$cli_log"
  die "CLI exited with status $cli_rc"
fi
if ! grep -Eq '^identity binding verifies: +true$' "$cli_log"; then
  show_log "$cli_log"
  die "CLI output lacks the identity-binding success marker"
fi
if ! grep -Eq '^Final resolved trust score A -> C on node C: [0-9]' "$cli_log"; then
  show_log "$cli_log"
  die "CLI output lacks a resolved trust score on node C"
fi
log "CLI OK"

# ---- (b) Browser -----------------------------------------------------------------------------
log "starting the browser node (limit ${browser_timeout}s)"
mkdir -p "$WORK/browser-home" "$WORK/browser-tmp"
browser_log="$WORK/browser.log"
pp=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
LAPISNET_KEYSTORE_PASSPHRASE="$pp" LAPISNET_HOME="$WORK/browser-home" \
  JAVA_OPTS="-Djava.io.tmpdir=$WORK/browser-tmp" \
  "$browser_root/bin/lapis-net-browser" >"$browser_log" 2>&1 </dev/null &
browser_pid=$!
PIDS="$PIDS $browser_pid"

# http_get <path>: stores the body in $WORK/body and the headers in $WORK/headers, prints the status.
http_get() {
  local code
  code=$(curl -s -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}' --max-time 3 \
    "http://127.0.0.1:${BROWSER_PORT}$1" 2>/dev/null) || true
  printf '%s\n' "${code:-000}"
}

browser_fail() {
  show_log "$browser_log"
  die "$1"
}

waited=0
while :; do
  kill -0 "$browser_pid" 2>/dev/null || browser_fail "browser process exited before it became ready"
  [[ "$(http_get /)" == "200" ]] && break
  ((waited < browser_timeout)) || browser_fail "browser did not answer 200 on / within ${browser_timeout}s"
  sleep 1
  waited=$((waited + 1))
done
log "browser answered after about ${waited}s"

grep -Fq '<title>Lapis Net - Minimal Browser</title>' "$WORK/body" || browser_fail "/ lacks the expected page title"

[[ "$(http_get /api/identity)" == "200" ]] || browser_fail "/api/identity did not return 200"
grep -Eiq '^content-type:.*application/json' "$WORK/headers" || browser_fail "/api/identity is not application/json"
grep -Eq '"fingerprint" *: *"[0-9a-f]+"' "$WORK/body" || browser_fail "/api/identity lacks a hex fingerprint"
grep -Eq '"peerId" *: *"12D3Koo' "$WORK/body" || browser_fail "/api/identity lacks a libp2p peer id"

[[ "$(http_get /api/peers)" == "200" ]] || browser_fail "/api/peers did not return 200"
grep -Eiq '^content-type:.*application/json' "$WORK/headers" || browser_fail "/api/peers is not application/json"

# SIGTERM is the expected way to stop a node: 143 (128+15) or a clean 0 both count as success.
kill -TERM "$browser_pid" 2>/dev/null || true
if ! wait_deadline "$browser_pid" 20; then
  browser_fail "browser did not stop within 20s of SIGTERM"
fi
browser_rc=0
wait "$browser_pid" || browser_rc=$?
PIDS=${PIDS/ $browser_pid/}
if [[ "$browser_rc" -ne 0 && "$browser_rc" -ne 143 ]]; then
  browser_fail "browser exited with status $browser_rc after SIGTERM"
fi

identity_file="$WORK/browser-home/identity/default.lnid"
if [[ -z "$(find "$identity_file" -perm 0600 2>/dev/null)" ]]; then
  browser_fail "encrypted identity file missing or its mode is not 0600 ($identity_file)"
fi

# The passphrase is fed to grep through stdin so it never shows up in a process listing. On a hit
# the log is deliberately NOT printed.
if grep -Fq -f - "$browser_log" <<<"$pp"; then
  die "the keystore passphrase appears in the browser log"
fi
unset pp
log "browser OK"

log "smoke test passed"
