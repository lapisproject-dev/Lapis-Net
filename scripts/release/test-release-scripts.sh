#!/usr/bin/env bash
# Offline test harness for the release scripts (no network, no GitHub, no Gradle).
#   test-release-scripts.sh                                   all offline tests
#   test-release-scripts.sh --with-dist <cli.zip> <browser.zip>   additionally smoke-test real ZIPs
#
# RELEASE_SCRIPTS_DIR overrides the directory holding the scripts under test (used to run the suite
# against deliberately broken copies and prove that a regression turns the matching test red).
# Every case asserts the exit status AND a fragment of the message, so a case cannot pass for the
# wrong reason. Needs: bash, git, python3 (the smoke-test cases are skipped without it).
#
# RELEASE_TESTS_STRICT=1 turns every skip that is caused by the machine (python3 missing, port 7878
# busy, a checksum tool missing) into a failure - this is what CI sets. The exit status is non-zero
# whenever a case failed.
set -uo pipefail
umask 077
unset GITHUB_OUTPUT GITHUB_ACTIONS GH_TOKEN GH_BIN SHA256_TOOL KEEP_SMOKE_DIR SMOKE_SKIP_JAVA_CHECK

S="${RELEASE_SCRIPTS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DIST_CLI="" DIST_BROWSER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-dist) DIST_CLI="${2-}"; DIST_BROWSER="${3-}"; shift 3 ;;
    *) echo "unknown argument '$1'" >&2; exit 2 ;;
  esac
done

T=$(mktemp -d "${TMPDIR:-/tmp}/lapisnet-reltest.XXXXXX")
LISTENER_PID=""
cleanup() {
  [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

PASS=0 FAIL=0 SKIP=0
ok() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad() {
  FAIL=$((FAIL + 1))
  printf '  FAIL  %s\n' "$1"
  [[ -n "${2:-}" ]] && printf '        %s\n' "$2"
  return 0
}
skip() { SKIP=$((SKIP + 1)); printf '  skip  %s (%s)\n' "$1" "$2"; }
# skip_env: a case that cannot run because of the machine (python3 missing, port 7878 busy, a
# checksum tool missing). A normal run only reports it; with RELEASE_TESTS_STRICT=1 (CI) it is a
# failure, so a runner that silently lost a dependency can never turn the harness green by skipping.
# `skip` stays for cases that are skipped on purpose (the real ZIPs without --with-dist).
skip_env() {
  if [[ "${RELEASE_TESTS_STRICT:-}" == "1" ]]; then
    bad "$1" "cannot run: $2 (RELEASE_TESTS_STRICT=1 does not allow skipping it)"
  else
    skip "$1" "$2"
  fi
}

OUT="" RC=0
run() { OUT=$("$@" 2>&1) && RC=0 || RC=$?; }

# expect_ok <name> <fragment> cmd...   /   expect_fail <name> <fragment> cmd...
expect_ok() {
  local name="$1" frag="$2"
  shift 2
  run "$@"
  if [[ $RC -eq 0 && "$OUT" == *"$frag"* ]]; then ok "$name"; else bad "$name" "rc=$RC, wanted success containing '$frag'; output: $(printf '%s' "$OUT" | tail -n 3 | tr '\n' '|')"; fi
}
expect_fail() {
  local name="$1" frag="$2"
  shift 2
  run "$@"
  if [[ $RC -ne 0 && "$OUT" == *"$frag"* ]]; then ok "$name"; else bad "$name" "rc=$RC, wanted failure containing '$frag'; output: $(printf '%s' "$OUT" | tail -n 3 | tr '\n' '|')"; fi
}
assert_contains() { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "missing '$3'"; fi; }
assert_lacks() { if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "unexpected '$3'"; fi; }

HAVE_PY=true
command -v python3 >/dev/null 2>&1 || HAVE_PY=false

# ================================================================================================
echo "== static checks"
for f in lib.sh resolve-context.sh verify-tag.sh smoke-test-dist.sh checksums.sh publish.sh; do
  if bash -n "$S/$f" 2>/dev/null; then ok "bash -n $f"; else bad "bash -n $f"; fi
done
for f in resolve-context.sh verify-tag.sh smoke-test-dist.sh checksums.sh publish.sh; do
  if [[ -x "$S/$f" ]]; then ok "$f is executable"; else bad "$f is executable"; fi
done
# Bash 3.2 / portability lint (no shellcheck on every machine): constructs that break on macOS.
forbidden='mapfile|readarray|declare -A|local -A|wait -n|sort -V|readlink -f|grep -P|sed -i|stat -c|\$\{[A-Za-z_]+(,,|\^\^)\}|(^|[[:space:];|&(])timeout '
hits=""
for f in lib.sh resolve-context.sh verify-tag.sh smoke-test-dist.sh checksums.sh publish.sh; do
  h=$(grep -vE '^[[:space:]]*#' "$S/$f" | grep -nE "$forbidden" || true)
  [[ -z "$h" ]] || hits="$hits $f: $h"
done
if [[ -z "$hits" ]]; then ok "no Bash-3.2-incompatible constructs"; else bad "no Bash-3.2-incompatible constructs" "$hits"; fi

# ================================================================================================
echo "== tag format"
t_valid() { ( . "$S/lib.sh"; is_valid_tag "$1" ); }
for v in v0.2.0 v10.20.30; do
  if t_valid "$v"; then ok "accepts $v"; else bad "accepts $v"; fi
done
nl_tag=$(printf 'v1.2.3\nx')
for v in 'v1.2' '1.2.3' 'v1.2.3-rc1' 'v01.2.3x' 'v1.2.3;id' "$nl_tag" '' 'refs/tags/v1.2.3' 'v1.2.3 ' 'V1.2.3' 'v1.2.3.4' 'v1111111.2.3' 'v1.2.99999999999999999999999999'; do
  if t_valid "$v"; then bad "rejects '$(printf '%s' "$v" | tr '\n' '~')'"; else ok "rejects '$(printf '%s' "$v" | tr '\n' '~')'"; fi
done

echo "== semver_gt"
t_gt() { ( . "$S/lib.sh"; semver_gt "$1" "$2" ); }
if t_gt v0.10.0 v0.9.9; then ok "0.10.0 > 0.9.9 (numeric, not lexical)"; else bad "0.10.0 > 0.9.9"; fi
if t_gt v1.0.0 v0.99.99; then ok "1.0.0 > 0.99.99"; else bad "1.0.0 > 0.99.99"; fi
if t_gt v0.2.0 v0.2.0; then bad "equal is not greater"; else ok "equal is not greater"; fi
if t_gt v0.2.0 v0.10.0; then bad "0.2.0 not > 0.10.0"; else ok "0.2.0 not > 0.10.0"; fi

# ================================================================================================
echo "== resolve-context"
rc_env() { env -u GITHUB_OUTPUT "$@" "$S/resolve-context.sh"; }
expect_ok "push of a tag" "mode=tag" rc_env EVENT_NAME=push GIT_REF=refs/tags/v0.2.0 REF_NAME=v0.2.0
assert_contains "push publishes" "$OUT" "publish=true"
expect_fail "push of a branch" "not a tag push" rc_env EVENT_NAME=push GIT_REF=refs/heads/master REF_NAME=master
expect_fail "push of a malformed tag" "vX.Y.Z" rc_env EVENT_NAME=push GIT_REF=refs/tags/v1.2 REF_NAME=v1.2
expect_fail "push: ref and ref_name disagree" "not a tag push" rc_env EVENT_NAME=push GIT_REF=refs/heads/v0.2.0 REF_NAME=v0.2.0
expect_fail "dispatch from a feature branch" "only allowed from master" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/feature/x REF_NAME=feature/x INPUT_TAG= INPUT_PUBLISH=false
expect_fail "dispatch from a tag ref" "only allowed from master" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/tags/v0.2.0 REF_NAME=v0.2.0 INPUT_TAG= INPUT_PUBLISH=false
expect_fail "dispatch publish=true without tag" "requires a tag" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/master REF_NAME=master INPUT_TAG= INPUT_PUBLISH=true
expect_ok "dispatch snapshot" "mode=snapshot" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/master REF_NAME=master INPUT_TAG= INPUT_PUBLISH=false
assert_contains "snapshot never publishes" "$OUT" "publish=false"
expect_ok "dispatch tag without publish" "publish=false" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/master REF_NAME=master INPUT_TAG=v0.2.0 INPUT_PUBLISH=false
expect_ok "dispatch tag with publish" "publish=true" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/master REF_NAME=master INPUT_TAG=v0.2.0 INPUT_PUBLISH=true
expect_fail "dispatch with malformed tag" "vX.Y.Z" rc_env EVENT_NAME=workflow_dispatch GIT_REF=refs/heads/master REF_NAME=master INPUT_TAG='v1.2.3;id' INPUT_PUBLISH=true
expect_fail "unsupported event" "unsupported event" rc_env EVENT_NAME=pull_request GIT_REF=refs/pull/1/merge REF_NAME=1/merge
expect_fail "empty event" "unsupported event" rc_env EVENT_NAME= GIT_REF= REF_NAME=

# ================================================================================================
echo "== verify-tag (throw-away repository)"
ORIGIN="$T/origin.git"
REPO="$T/repo"
git init -q --bare "$ORIGIN"
git init -q "$REPO"
g() { git -C "$REPO" "$@"; }
g symbolic-ref HEAD refs/heads/master
g config user.name tester
g config user.email tester@example.invalid
g config commit.gpgsign false
g config tag.gpgsign false
g remote add origin "$ORIGIN"
write_build() { printf '%s\n' "$1" >"$REPO/build.gradle.kts"; }
commit_all() { g add -A && g commit -q -m "$1"; }

write_build 'allprojects {
    version = "0.2.0"
}'
commit_all c1
C1=$(g rev-parse HEAD)
g tag -a v0.2.0 -m "v0.2.0 - first test release"
g tag -a v0.3.0 -m "v0.3.0 - wrong version"
g tag v0.2.1

g checkout -q -b side
write_build 'allprojects {
    version = "0.4.0"
}'
commit_all side
g tag -a v0.4.0 -m "v0.4.0 - side branch"
g checkout -q master

write_build 'allprojects {
    version = "0.5.0"
}
subprojects {
    version = "0.5.0"
}'
commit_all dup
g tag -a v0.5.0 -m "v0.5.0 - two version lines"

write_build 'allprojects {
    group = "x"
}'
commit_all none
g tag -a v0.6.0 -m "v0.6.0 - no version line"

write_build '// version = "9.9.9"
allprojects {
    version = "0.7.0"
}'
commit_all final
g tag -a v0.7.0 -m "v0.7.0 - good (comment line with another version)"
g push -q origin master
g fetch -q origin

write_build 'allprojects {
    version = "0.8.0"
}'
commit_all unpushed
g tag -a v0.8.0 -m "v0.8.0 - on local master only"

vt() { "$S/verify-tag.sh" --repo-dir "$REPO" "$@"; }
vt_local() { vt --master-ref refs/heads/master "$@"; }
expect_ok "happy path (annotated, on master, version matches)" "version=0.2.0" vt_local --tag v0.2.0
assert_contains "happy path reports the commit" "$OUT" "commit=$C1"
assert_contains "happy path reports the annotation subject" "$OUT" "title=v0.2.0 - first test release"
expect_ok "version line in a comment is ignored" "version=0.7.0" vt --tag v0.7.0
expect_fail "tag/version mismatch" "declares version 0.2.0" vt_local --tag v0.3.0
expect_fail "lightweight tag" "lightweight" vt_local --tag v0.2.1
expect_fail "tag on a side branch" "not on master" vt_local --tag v0.4.0
expect_fail "two version lines" "found 2" vt_local --tag v0.5.0
expect_fail "no version line" "found 0" vt_local --tag v0.6.0
expect_fail "tag does not exist" "does not exist" vt_local --tag v9.9.9
expect_fail "malformed tag" "vX.Y.Z" vt_local --tag 'v1.2'
expect_fail "missing --tag" "--tag is required" vt_local
expect_fail "unknown master ref" "not found" vt --master-ref refs/remotes/origin/nope --tag v0.2.0
expect_fail "commit only on local master, default origin/master ref" "not on master" vt --tag v0.8.0
expect_ok "same tag passes against local master" "version=0.8.0" vt_local --tag v0.8.0
g branch v0.2.0 side 2>/dev/null
expect_ok "a branch named like the tag cannot shadow it" "commit=$C1" vt_local --tag v0.2.0
assert_contains "... and the version stays the tag's" "$OUT" "version=0.2.0"

# ================================================================================================
echo "== checksums"
CS="$T/cs"
mkdir -p "$CS"
printf 'alpha-%s' "$$" >"$CS/a.zip"
printf 'beta' >"$CS/b.zip"
expect_ok "generate" "wrote" "$S/checksums.sh" generate "$CS" "$CS/a.zip" "$CS/b.zip"
expect_ok "verify" "checksums OK" "$S/checksums.sh" verify "$CS"
sums=$(cat "$CS/SHA256SUMS")
assert_contains "format is '<hex>  <name>'" "$sums" "  a.zip"
expect_fail "generate rejects a directory with extra files" "does not contain exactly" "$S/checksums.sh" generate "$CS" "$CS/a.zip"
cp "$CS/a.zip" "$T/a.orig"
printf 'X' | dd of="$CS/a.zip" bs=1 seek=2 conv=notrunc 2>/dev/null
expect_fail "flipped byte" "checksum mismatch for a.zip" "$S/checksums.sh" verify "$CS"
cp "$T/a.orig" "$CS/a.zip"
printf 'extra' >"$CS/c.zip"
expect_fail "unlisted extra file" "differ" "$S/checksums.sh" verify "$CS"
rm "$CS/c.zip"
rm "$CS/b.zip"
expect_fail "listed file missing" "listed file is missing: b.zip" "$S/checksums.sh" verify "$CS"
printf 'beta' >"$CS/b.zip"
printf 'not a checksum line\n' >"$CS/SHA256SUMS"
expect_fail "malformed SHA256SUMS" "malformed" "$S/checksums.sh" verify "$CS"
expect_fail "no SHA256SUMS" "missing" "$S/checksums.sh" verify "$T"
if command -v shasum >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1; then
  "$S/checksums.sh" generate "$CS" "$CS/a.zip" "$CS/b.zip" >/dev/null 2>&1
  d1=$(cat "$CS/SHA256SUMS")
  SHA256_TOOL=shasum "$S/checksums.sh" generate "$CS" "$CS/a.zip" "$CS/b.zip" >/dev/null 2>&1
  d2=$(cat "$CS/SHA256SUMS")
  if [[ "$d1" == "$d2" ]]; then ok "sha256sum and shasum agree"; else bad "sha256sum and shasum agree"; fi
  expect_ok "verify works with shasum only" "checksums OK" env SHA256_TOOL=shasum "$S/checksums.sh" verify "$CS"
else
  skip_env "sha256sum/shasum agreement" "one of the tools is missing"
fi

# ================================================================================================
echo "== documented checksum commands (README.adoc, docs/releasing.adoc)"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOC_SHA256SUM='sha256sum -c --ignore-missing SHA256SUMS'
DOC_SHASUM='awk '"'"'$2 == "<file>"'"'"' SHA256SUMS | shasum -a 256 -c -'
for doc in README.adoc docs/releasing.adoc; do
  if grep -qF -- "$DOC_SHA256SUM" "$REPO_ROOT/$doc"; then ok "$doc documents: $DOC_SHA256SUM"; else bad "$doc documents: $DOC_SHA256SUM"; fi
  if grep -qF -- "$DOC_SHASUM" "$REPO_ROOT/$doc"; then ok "$doc documents the awk | shasum command"; else bad "$doc documents the awk | shasum command"; fi
done
# The downloader holds ONE of the two ZIPs, SHA256SUMS lists both: that is the case the commands exist for.
DL="$T/dl"
mkdir -p "$DL"
printf 'cli-bytes' >"$DL/lapis-net-cli-1.2.3.zip"
printf 'browser-bytes' >"$DL/lapis-net-browser-1.2.3.zip"
"$S/checksums.sh" generate "$DL" "$DL/lapis-net-browser-1.2.3.zip" "$DL/lapis-net-cli-1.2.3.zip" >/dev/null 2>&1
rm "$DL/lapis-net-browser-1.2.3.zip"
doc_cmd() { local cmd="${1//<file>/$2}"; ( cd "$DL" && bash -c "$cmd" ) 2>&1; }
if command -v sha256sum >/dev/null 2>&1; then
  run doc_cmd "$DOC_SHA256SUM" lapis-net-cli-1.2.3.zip
  if [[ $RC -eq 0 && "$OUT" == *"lapis-net-cli-1.2.3.zip: OK"* ]]; then ok "sha256sum command: matching file passes"; else bad "sha256sum command: matching file passes" "rc=$RC $OUT"; fi
else
  skip_env "sha256sum documented command" "sha256sum not found"
fi
if command -v shasum >/dev/null 2>&1; then
  run doc_cmd "$DOC_SHASUM" lapis-net-cli-1.2.3.zip
  if [[ $RC -eq 0 && "$OUT" == *"lapis-net-cli-1.2.3.zip: OK"* ]]; then ok "shasum command: matching file passes"; else bad "shasum command: matching file passes" "rc=$RC $OUT"; fi
  run doc_cmd "$DOC_SHASUM" lapis-net-cli-1.2.4.zip
  if [[ $RC -ne 0 ]]; then ok "shasum command: a mistyped name is an error, not a silent success"; else bad "shasum command: a mistyped name is an error, not a silent success" "rc=$RC $OUT"; fi
  # a name that is a regex-prefix of another must not select it ('.' is literal in awk's string comparison)
  run doc_cmd "$DOC_SHASUM" 'lapis-net-cli-1x2.3.zip'
  if [[ $RC -ne 0 ]]; then ok "shasum command: the name is matched literally"; else bad "shasum command: the name is matched literally" "rc=$RC $OUT"; fi
  cp "$DL/lapis-net-cli-1.2.3.zip" "$T/cli.orig"
  printf 'X' >>"$DL/lapis-net-cli-1.2.3.zip"
  run doc_cmd "$DOC_SHASUM" lapis-net-cli-1.2.3.zip
  if [[ $RC -ne 0 && "$OUT" == *"FAILED"* ]]; then ok "shasum command: a tampered file fails"; else bad "shasum command: a tampered file fails" "rc=$RC $OUT"; fi
  if command -v sha256sum >/dev/null 2>&1; then
    run doc_cmd "$DOC_SHA256SUM" lapis-net-cli-1.2.3.zip
    if [[ $RC -ne 0 && "$OUT" == *"FAILED"* ]]; then ok "sha256sum command: a tampered file fails"; else bad "sha256sum command: a tampered file fails" "rc=$RC $OUT"; fi
  fi
  cp "$T/cli.orig" "$DL/lapis-net-cli-1.2.3.zip"
else
  skip_env "shasum documented command" "shasum not found"
fi

# ================================================================================================
echo "== smoke-test-dist (synthetic archives)"
ZD="$T/zips"
mkdir -p "$ZD"
FAKE="$T/fake"
mkdir -p "$FAKE"
cat >"$FAKE/fake_server.py" <<'PYEOF'
import http.server, os
home = os.environ["LAPISNET_HOME"]
pp = os.environ.get("LAPISNET_KEYSTORE_PASSPHRASE", "")
d = os.path.join(home, "identity")
os.makedirs(d, exist_ok=True)
mode = 0o644 if os.environ.get("FAKE_BAD_PERM") == "1" else 0o600
fd = os.open(os.path.join(d, "default.lnid"), os.O_WRONLY | os.O_CREAT, mode)
os.fchmod(fd, mode)
os.close(fd)
if os.environ.get("FAKE_LEAK") == "1":
    print("passphrase is " + pp, flush=True)
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path == "/":
            body, ct = b"<html><head><title>Lapis Net - Minimal Browser</title></head></html>", "text/html"
        elif self.path == "/api/identity":
            body, ct = b'{"fingerprint":"abcdef0123","peerId":"12D3KooWFake"}', "application/json"
        elif self.path == "/api/peers":
            body, ct = b"[]", "application/json"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(("127.0.0.1", 7878), H).serve_forever()
PYEOF
cat >"$FAKE/cli.sh" <<'SHEOF'
#!/bin/sh
case "${FAKE_CLI:-ok}" in
  ok) echo "identity binding verifies:      true"; echo "Final resolved trust score A -> C on node C: 0.9" ;;
  nomarker) echo "identity binding verifies:      null"; echo "Final resolved trust score A -> C on node C: null" ;;
  fail) echo "boom"; exit 3 ;;
  # exec: the shell is replaced by sleep, so the TERM that smoke-test-dist.sh sends to this PID hits
  # the sleep itself. Without it only the shell dies and an orphaned `sleep 600` outlives the run.
  hang) [ -n "${FAKE_PIDFILE:-}" ] && echo $$ >"$FAKE_PIDFILE"; exec sleep 600 ;;
esac
SHEOF
cat >"$FAKE/browser.sh" <<'SHEOF'
#!/bin/sh
exec python3 "$(dirname "$0")/../lib/fake_server.py"
SHEOF
# mkzip <out> <root> <cli|browser>; the archive layout is varied through MK_MODE
mkzip() {
  FAKE_DIR="$FAKE" python3 - "$1" "$2" "$3" <<'PYEOF'
import os, sys, zipfile
out, root, mod = sys.argv[1], sys.argv[2], sys.argv[3]
fake = os.environ["FAKE_DIR"]
mode = os.environ.get("MK_MODE", "good")
def add(z, name, data, exe=False):
    i = zipfile.ZipInfo(name)
    i.external_attr = (0o755 if exe else 0o644) << 16
    z.writestr(i, data)
def read(n):
    with open(os.path.join(fake, n)) as f:
        return f.read()
with zipfile.ZipFile(out, "w") as z:
    if mode != "nobin":
        add(z, root + "/bin/lapis-net-" + mod, read("cli.sh" if mod == "cli" else "browser.sh"), exe=True)
    add(z, root + "/lib/dummy.jar", "x")
    if mod == "browser":
        add(z, root + "/lib/fake_server.py", read("fake_server.py"))
    if mode == "tworoots":
        add(z, "other-root/lib/x.jar", "x")
    if mode == "rootfile":
        add(z, "stray.txt", "x")
    if mode == "traversal":
        add(z, root + "/../evil", "x")
PYEOF
}
if ! $HAVE_PY; then
  skip_env "synthetic smoke-test cases" "python3 not found"
else
  mkzip "$ZD/cli.zip" lapis-net-cli-0.2.0 cli
  mv "$ZD/cli.zip" "$ZD/lapis-net-cli-0.2.0.zip"
  mkzip "$ZD/browser.zip" lapis-net-browser-0.2.0 browser
  mv "$ZD/browser.zip" "$ZD/lapis-net-browser-0.2.0.zip"
  GOOD_CLI="$ZD/lapis-net-cli-0.2.0.zip"
  GOOD_BROWSER="$ZD/lapis-net-browser-0.2.0.zip"
  st() { env SMOKE_SKIP_JAVA_CHECK=1 "$@"; }
  sm() { local c="$1" b="$2"; shift 2; st "$@" "$S/smoke-test-dist.sh" --cli-zip "$c" --browser-zip "$b" --cli-timeout 20 --browser-timeout 20; }

  # --- failures that happen before anything is started (no port needed)
  head -c 200 "$GOOD_CLI" >"$ZD/lapis-net-cli-0.3.0.zip"
  expect_fail "truncated zip" "corrupt" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  rm "$ZD/lapis-net-cli-0.3.0.zip"
  MK_MODE=nobin mkzip "$ZD/lapis-net-cli-0.3.0.zip" lapis-net-cli-0.3.0 cli
  expect_fail "zip without bin/" "missing or not executable" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  MK_MODE=tworoots mkzip "$ZD/lapis-net-cli-0.3.0.zip" lapis-net-cli-0.3.0 cli
  expect_fail "zip with two root directories" "exactly one root directory" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  MK_MODE=rootfile mkzip "$ZD/lapis-net-cli-0.3.0.zip" lapis-net-cli-0.3.0 cli
  expect_fail "file directly in the archive root" "outside a single root" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  MK_MODE=traversal mkzip "$ZD/lapis-net-cli-0.3.0.zip" lapis-net-cli-0.3.0 cli
  expect_fail "path traversal entry" "parent-relative" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  mkzip "$ZD/lapis-net-cli-0.3.0.zip" lapis-net-cli-0.9.9 cli
  expect_fail "version in root dir differs from file name" "does not match the file name" sm "$ZD/lapis-net-cli-0.3.0.zip" "$GOOD_BROWSER"
  rm "$ZD/lapis-net-cli-0.3.0.zip"
  cp "$GOOD_CLI" "$ZD/cli-wrong-name.zip"
  expect_fail "unexpected file name" "unexpected file name" sm "$ZD/cli-wrong-name.zip" "$GOOD_BROWSER"
  rm "$ZD/cli-wrong-name.zip"

  # --- cases that start fake distributions; they need the fixed browser port 7878
  if (exec 3<>/dev/tcp/127.0.0.1/7878) 2>/dev/null; then
    skip_env "cases that need port 7878" "port 7878 is busy on this machine"
  else
    expect_ok "complete run with fake distributions" "smoke test passed" sm "$GOOD_CLI" "$GOOD_BROWSER"
    expect_fail "CLI without success markers" "success marker" sm "$GOOD_CLI" "$GOOD_BROWSER" FAKE_CLI=nomarker
    expect_fail "CLI exit status" "exited with status 3" sm "$GOOD_CLI" "$GOOD_BROWSER" FAKE_CLI=fail
    expect_fail "CLI hang hits the deadline" "did not finish within" env SMOKE_SKIP_JAVA_CHECK=1 FAKE_CLI=hang FAKE_PIDFILE="$T/hang.pid" "$S/smoke-test-dist.sh" --cli-zip "$GOOD_CLI" --browser-zip "$GOOD_BROWSER" --cli-timeout 3 --browser-timeout 10
    # The pid file holds the pid of the hanging fake CLI (the sleep itself, thanks to exec). It must be
    # gone: checking this pid, not `pgrep -f "sleep 600"`, cannot hit an unrelated process.
    hang_pid=$(cat "$T/hang.pid" 2>/dev/null || true)
    if [[ "$hang_pid" =~ ^[0-9]+$ ]]; then
      if kill -0 "$hang_pid" 2>/dev/null; then
        bad "no orphaned sleep after the CLI hang" "pid $hang_pid is still alive"
        kill -KILL "$hang_pid" 2>/dev/null
      else
        ok "no orphaned sleep after the CLI hang"
      fi
    else
      bad "no orphaned sleep after the CLI hang" "the fake CLI did not record its pid"
    fi
    expect_fail "passphrase leaked into the log" "passphrase appears" sm "$GOOD_CLI" "$GOOD_BROWSER" FAKE_LEAK=1
    assert_lacks "... and the log is not printed" "$OUT" "passphrase is "
    expect_fail "identity file with the wrong mode" "not 0600" sm "$GOOD_CLI" "$GOOD_BROWSER" FAKE_BAD_PERM=1
    if pgrep -f "fake_server.py" >/dev/null 2>&1; then bad "no orphaned fake server after the runs"; else ok "no orphaned fake server after the runs"; fi
    if ls "${TMPDIR:-/tmp}" 2>/dev/null | grep -q '^lapisnet-smoke\.'; then bad "smoke temp directories removed"; else ok "smoke temp directories removed"; fi

    python3 -m http.server 7878 --bind 127.0.0.1 --directory "$T" >/dev/null 2>&1 &
    LISTENER_PID=$!
    sleep 1
    expect_fail "port 7878 busy aborts before starting anything" "port 7878 busy" sm "$GOOD_CLI" "$GOOD_BROWSER"
    kill "$LISTENER_PID" 2>/dev/null
    wait "$LISTENER_PID" 2>/dev/null
    LISTENER_PID=""
  fi
fi

# ================================================================================================
echo "== publish (dry run and stub gh)"
mk_assets() {
  local dir="$1" v="$2"
  mkdir -p "$dir"
  printf 'browser-%s' "$v" >"$dir/lapis-net-browser-$v.zip"
  printf 'cli-%s' "$v" >"$dir/lapis-net-cli-$v.zip"
  "$S/checksums.sh" generate "$dir" "$dir/lapis-net-browser-$v.zip" "$dir/lapis-net-cli-$v.zip" >/dev/null 2>&1
}
A="$T/assets-0.2.0"
mk_assets "$A" 0.2.0
GOODNOTES="$T/notes-good.adoc"
printf '%s\n' 'Release 0.2.0 adds the release pipeline.' '' '* Distribution ZIPs for the browser node and the CLI demo' '* A SHA256SUMS file next to them' >"$GOODNOTES"
SHORTNOTES="$T/notes-short.adoc"
printf 'too short\n' >"$SHORTNOTES"
EMPTYNOTES="$T/notes-empty.adoc"
: >"$EMPTYNOTES"
HEADNOTES="$T/notes-heading.adoc"
printf '%s\n' '== Heading' '' 'Plenty of ordinary text so that the length check is not what fails here.' >"$HEADNOTES"
LINKNOTES="$T/notes-link.adoc"
printf '%s\n' 'Plenty of ordinary text so that the length check is not what fails here, see link:foo.adoc[the docs].' >"$LINKNOTES"

# A remote for the tag check of publish.sh. v0.2.0 is an annotated tag on C1 (the commit "the build
# verified"), v0.2.1 is lightweight, v0.2.2 does not exist. $C_OTHER is any other commit.
PORIGIN="$T/porigin.git"
git init -q --bare "$PORIGIN"
C_OTHER=$(g rev-parse HEAD)
[[ "$C_OTHER" != "$C1" ]] || echo "test setup error: need a second commit" >&2
set_ptag() { g tag -f -a "$1" -m "$1 test" "$2" >/dev/null 2>&1 && g push -q -f "$PORIGIN" "refs/tags/$1" 2>/dev/null; }
set_ptag v0.2.0 "$C1"
g push -q -f "$PORIGIN" refs/tags/v0.2.1 2>/dev/null
mk_assets "$T/assets-0.2.1" 0.2.1
mk_assets "$T/assets-0.2.2" 0.2.2

pub_dry() { env GH_BIN=/nonexistent/gh "$S/publish.sh" --tag v0.2.0 --assets-dir "$A" --repo owner/name --dry-run "$@"; }
expect_ok "dry run, new release: draft create, then publish" "DRY-RUN: gh release create v0.2.0" pub_dry --assume-exists no --notes-file "$GOODNOTES" --title "v0.2.0 - test"
assert_contains "... created as a draft" "$OUT" "--draft"
assert_contains "... with a verified tag" "$OUT" "--verify-tag"
assert_contains "... then published" "$OUT" "release edit v0.2.0 --repo owner/name --draft=false"
expect_fail "dry run, new release, no notes file" "no --notes-file" pub_dry --assume-exists no
expect_fail "dry run, new release, notes file missing" "not found" pub_dry --assume-exists no --notes-file "$T/does-not-exist.adoc"
expect_fail "dry run, new release, empty notes" "empty or too short" pub_dry --assume-exists no --notes-file "$EMPTYNOTES"
expect_fail "dry run, new release, too short notes" "empty or too short" pub_dry --assume-exists no --notes-file "$SHORTNOTES"
assert_lacks "... and no create is emitted" "$OUT" "release create"
expect_fail "AsciiDoc heading is rejected" "AsciiDoc-only" pub_dry --assume-exists no --notes-file "$HEADNOTES"
expect_fail "AsciiDoc inline link is rejected" "AsciiDoc-only" pub_dry --assume-exists no --notes-file "$LINKNOTES"
expect_ok "dry run, existing release, no notes: only assets" "would compare the assets already on the release by SHA-256" pub_dry --assume-exists yes
assert_contains "... published assets are never replaced" "$OUT" "published assets are never replaced"
assert_lacks "... no blind upload is emitted" "$OUT" "DRY-RUN: gh release upload"
assert_lacks "... notes untouched" "$OUT" "--notes-file"
assert_lacks "... title untouched" "$OUT" "--title"
assert_lacks "... not re-created" "$OUT" "release create"
expect_ok "dry run, existing release, notes file missing: keep notes" "keeping the existing title and notes" pub_dry --assume-exists yes --notes-file "$T/docs/release-notes/v0.2.0.adoc"
assert_lacks "... still no notes edit" "$OUT" "--notes-file"
expect_ok "dry run, existing release, notes file present: notes updated" "release edit v0.2.0 --repo owner/name --notes-file" pub_dry --assume-exists yes --notes-file "$GOODNOTES"
expect_fail "dry run requires --assume-exists" "--assume-exists" pub_dry
expect_ok "dry run with --expect-commit checks the tag on the remote" "DRY-RUN: gh release create v0.2.0" pub_dry --assume-exists no --notes-file "$GOODNOTES" --expect-commit "$C1" --remote "$PORIGIN"
expect_fail "dry run with a wrong --expect-commit refuses" "now points to $C1" pub_dry --assume-exists no --notes-file "$GOODNOTES" --expect-commit "$C_OTHER" --remote "$PORIGIN"
expect_fail "--expect-commit must be a full 40-hex commit" "40-character" pub_dry --assume-exists no --notes-file "$GOODNOTES" --expect-commit "abc123"
expect_fail "--expect-commit rejects upper case and branch names" "40-character" pub_dry --assume-exists no --notes-file "$GOODNOTES" --expect-commit "master"
expect_fail "a real run without --expect-commit fails closed" "--expect-commit is required" env GH_BIN=/nonexistent/gh GH_TOKEN=dummy "$S/publish.sh" --tag v0.2.0 --assets-dir "$A" --repo owner/name --notes-file "$GOODNOTES"
expect_fail "non-dry run requires GH_TOKEN" "GH_TOKEN is not set" "$S/publish.sh" --tag v0.2.0 --assets-dir "$A" --repo owner/name --notes-file "$GOODNOTES"
expect_fail "malformed tag" "vX.Y.Z" "$S/publish.sh" --tag v0.2 --assets-dir "$A" --repo owner/name --dry-run --assume-exists yes
expect_fail "malformed repo" "OWNER/NAME" "$S/publish.sh" --tag v0.2.0 --assets-dir "$A" --repo 'owner/name;x' --dry-run --assume-exists yes
B="$T/assets-bad"
mk_assets "$B" 0.2.0
printf 'x' >"$B/stray.txt"
expect_fail "unexpected file in the assets directory" "must contain exactly" env GH_BIN=/nonexistent/gh "$S/publish.sh" --tag v0.2.0 --assets-dir "$B" --repo owner/name --dry-run --assume-exists yes
rm "$B/stray.txt"
printf 'tampered' >"$B/lapis-net-cli-0.2.0.zip"
expect_fail "assets that do not match SHA256SUMS" "checksum mismatch" env GH_BIN=/nonexistent/gh "$S/publish.sh" --tag v0.2.0 --assets-dir "$B" --repo owner/name --dry-run --assume-exists yes
mk_assets "$T/assets-wrongver" 0.3.0
expect_fail "assets of another version" "must contain exactly" env GH_BIN=/nonexistent/gh "$S/publish.sh" --tag v0.2.0 --assets-dir "$T/assets-wrongver" --repo owner/name --dry-run --assume-exists yes

# --- stateful stub gh
STUB="$T/gh-stub.sh"
cat >"$STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -u
echo "gh $*" >>"$STUB_LOG"
[[ "${1:-}" == release ]] || exit 2
sub="${2:-}"
shift 2
tag="" files="" skip_next=false positional=0 notes="" dir="" draft=false pattern="" clobber=false
for a in "$@"; do
  if $skip_next; then
    skip_next=false
    continue
  fi
  case "$a" in
    --repo | --title | --limit | --json | --jq | --pattern) skip_next=true ;;
    --notes-file) skip_next=true ;;
    --dir) skip_next=true ;;
    --*) ;;
    *)
      positional=$((positional + 1))
      if [[ $positional -eq 1 ]]; then tag="$a"; else files="$files$a"$'\n'; fi
      ;;
  esac
done
prev=""
for a in "$@"; do
  [[ "$prev" == "--notes-file" ]] && notes="$a"
  [[ "$prev" == "--dir" ]] && dir="$a"
  [[ "$prev" == "--pattern" ]] && pattern="$a"
  [[ "$a" == "--clobber" ]] && clobber=true
  [[ "$a" == "--draft" ]] && draft=true
  prev="$a"
done
mkdir -p "$STUB_STATE/remote"
touch "$STUB_STATE/releases.tsv"
case "$sub" in
  list) cat "$STUB_STATE/releases.tsv" ;;
  create)
    printf '%s\t%s\tfalse\n' "$tag" "$draft" >>"$STUB_STATE/releases.tsv"
    [[ -n "$notes" ]] && cp "$notes" "$STUB_STATE/notes-$tag.md"
    while IFS= read -r f; do [[ -n "$f" ]] && cp "$f" "$STUB_STATE/remote/"; done <<<"$files"
    # test hook: something happens right after the release was created (e.g. the tag is moved)
    [[ -n "${STUB_AFTER_CREATE:-}" ]] && "$STUB_AFTER_CREATE"
    ;;
  upload)
    # like the real gh: an asset that already exists is only replaced with --clobber
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      if [[ -e "$STUB_STATE/remote/$(basename "$f")" && "$clobber" != true ]]; then
        echo "HTTP 422: asset under the same name already exists: $(basename "$f")" >&2
        exit 1
      fi
      cp "$f" "$STUB_STATE/remote/"
    done <<<"$files"
    ;;
  view) ls "$STUB_STATE/remote/" ;;
  edit)
    [[ -n "$notes" ]] && cp "$notes" "$STUB_STATE/notes-$tag.md"
    for a in "$@"; do
      if [[ "$a" == "--draft=false" ]]; then
        awk -F'\t' -v t="$tag" 'BEGIN{OFS="\t"} $1==t{$2="false"} {print}' "$STUB_STATE/releases.tsv" >"$STUB_STATE/releases.new"
        mv "$STUB_STATE/releases.new" "$STUB_STATE/releases.tsv"
      fi
    done
    ;;
  download)
    if [[ -n "$pattern" && "$pattern" != "*" ]]; then
      [[ -f "$STUB_STATE/remote/$pattern" ]] && cp "$STUB_STATE/remote/$pattern" "$dir/"
    else
      cp "$STUB_STATE/remote/"* "$dir/"
    fi
    if [[ "${STUB_TAMPER:-}" == "1" ]]; then
      for z in "$dir"/*.zip; do printf 'x' >>"$z"; break; done
    fi
    ;;
  *) exit 2 ;;
esac
exit 0
STUBEOF
chmod +x "$STUB"
new_state() { rm -rf "$T/state"; mkdir -p "$T/state"; : >"$T/state.log"; if [[ -n "${1:-}" ]]; then printf '%b' "$1" >"$T/state/releases.tsv"; fi; }
pub_real() { env GH_BIN="$STUB" GH_TOKEN=dummy STUB_LOG="$T/state.log" STUB_STATE="$T/state" "$S/publish.sh" --tag v0.2.0 --assets-dir "$A" --repo owner/name --expect-commit "$C1" --remote "$PORIGIN" "$@"; }
# the same for another tag / assets directory / expected commit
pub_tag() {
  local t="$1" dir="$2" commit="$3"
  shift 3
  env GH_BIN="$STUB" GH_TOKEN=dummy STUB_LOG="$T/state.log" STUB_STATE="$T/state" "$S/publish.sh" --tag "$t" --assets-dir "$dir" --repo owner/name --expect-commit "$commit" --remote "$PORIGIN" "$@"
}
seed_remote() { mkdir -p "$T/state/remote" && cp "$1"/* "$T/state/remote/"; }
log_line() { grep -n "$1" "$T/state.log" | head -n 1 | cut -d: -f1; }

new_state 'v0.1.0\tfalse\tfalse\n'
expect_ok "stub: new release is created and published" "done" pub_real --notes-file "$GOODNOTES" --title "v0.2.0 - test"
calls=$(cat "$T/state.log")
assert_contains "stub: create as draft with verify-tag" "$calls" "release create v0.2.0 --repo owner/name --verify-tag --draft"
assert_contains "stub: highest version, Latest set" "$calls" "--draft=false --latest=true"
c=$(log_line "release create"); d=$(log_line "release download"); e=$(log_line "draft=false")
if [[ -n "$c" && -n "$d" && -n "$e" && "$c" -lt "$d" && "$d" -lt "$e" ]]; then ok "stub: order create -> download-and-verify -> publish"; else bad "stub: order create -> download-and-verify -> publish" "$c $d $e"; fi
body=$(cat "$T/state/notes-v0.2.0.md" 2>/dev/null || true)
assert_contains "stub: release text carries the notes" "$body" "adds the release pipeline"
assert_contains "stub: release text says the artifacts are unsigned" "$body" "not signed"
assert_contains "stub: published (draft flag cleared)" "$(cat "$T/state/releases.tsv")" "$(printf 'v0.2.0\tfalse')"

cp "$T/state.log" "$T/state.log.first"
: >"$T/state.log"
expect_ok "stub: second run against the existing release" "already exists" pub_real
calls=$(cat "$T/state.log")
assert_lacks "stub: second run does not create again" "$calls" "release create"
assert_lacks "stub: second run does not touch the notes" "$calls" "--notes-file"
assert_lacks "stub: second run does not touch Latest" "$calls" "--latest"
assert_lacks "stub: second run uploads nothing (all assets are identical)" "$calls" "release upload"
assert_contains "stub: second run reports the assets as unchanged" "$OUT" "asset lapis-net-cli-0.2.0.zip is unchanged"

new_state 'v0.99.0\tfalse\tfalse\nv0.1.0\tfalse\tfalse\n'
expect_ok "stub: older release created while a higher one exists" "done" pub_real --notes-file "$GOODNOTES"
assert_contains "stub: Latest is NOT taken over" "$(cat "$T/state.log")" "--draft=false --latest=false"

new_state 'v0.99.0\ttrue\tfalse\nv0.9.0\tfalse\ttrue\n'
expect_ok "stub: drafts and prereleases do not count for Latest" "done" pub_real --notes-file "$GOODNOTES"
assert_contains "stub: ... so this one becomes Latest" "$(cat "$T/state.log")" "--latest=true"

new_state 'v0.2.0\ttrue\tfalse\n'
expect_ok "stub: leftover draft is repaired and published" "publishing leftover draft" pub_real
assert_contains "stub: ... publish call present" "$(cat "$T/state.log")" "release edit v0.2.0 --repo owner/name --draft=false --latest=true"
assert_lacks "stub: ... without recreating it" "$(cat "$T/state.log")" "release create"

new_state 'v0.2.0\tfalse\tfalse\n'
expect_ok "stub: existing hand-written release keeps title and notes" "keeping the existing title and notes" pub_real
assert_lacks "stub: ... no edit call at all" "$(cat "$T/state.log")" "release edit"

new_state ''
expect_fail "stub: new release without notes file is refused" "no --notes-file" pub_real
assert_lacks "stub: ... nothing was created" "$(cat "$T/state.log")" "release create"

new_state ''
export STUB_TAMPER=1
expect_fail "stub: tampered download is detected before publishing" "mismatch" pub_real --notes-file "$GOODNOTES"
unset STUB_TAMPER
assert_lacks "stub: ... draft stays unpublished" "$(cat "$T/state.log")" "draft=false"

# ================================================================================================
echo "== publish: the tag must still point at the verified commit"
# A tag that was force-moved after the build verified it must never be published. The stub records
# every gh call, so "nothing was changed" is asserted on the log, not on a message.
set_ptag v0.2.0 "$C1"
new_state ''
expect_ok "tag check: an unmoved annotated tag is published" "done" pub_real --notes-file "$GOODNOTES"
assert_contains "tag check: ... release was created" "$(cat "$T/state.log")" "release create v0.2.0"

set_ptag v0.2.0 "$C_OTHER"
new_state ''
expect_fail "tag check: tag moved after the verification is refused" "now points to $C_OTHER, the build verified $C1" pub_real --notes-file "$GOODNOTES"
calls=$(cat "$T/state.log")
assert_lacks "tag check: ... no release was created" "$calls" "release create"
assert_lacks "tag check: ... nothing was uploaded" "$calls" "release upload"
assert_lacks "tag check: ... nothing was published" "$calls" "release edit"

new_state 'v0.2.0\ttrue\tfalse\n'
expect_fail "tag check: an existing draft is not changed or published for a moved tag" "now points to" pub_real
calls=$(cat "$T/state.log")
assert_lacks "tag check: ... no upload to the draft" "$calls" "release upload"
assert_lacks "tag check: ... draft not published" "$calls" "draft=false"

# moved between "release created" and "draft published": the check right before the publish call catches it
MOVE="$T/move-tag.sh"
cat >"$MOVE" <<MOVEEOF
#!/usr/bin/env bash
git -C "$REPO" tag -f -a v0.2.0 -m "moved after create" "$C_OTHER" >/dev/null 2>&1
git -C "$REPO" push -q -f "$PORIGIN" refs/tags/v0.2.0 2>/dev/null
MOVEEOF
chmod +x "$MOVE"
set_ptag v0.2.0 "$C1"
new_state ''
export STUB_AFTER_CREATE="$MOVE"
expect_fail "tag check: tag moved between create and publish is caught" "now points to $C_OTHER" pub_real --notes-file "$GOODNOTES"
unset STUB_AFTER_CREATE
calls=$(cat "$T/state.log")
assert_contains "tag check: ... the draft had been created" "$calls" "release create v0.2.0"
assert_lacks "tag check: ... but it was never published" "$calls" "draft=false"
assert_contains "tag check: ... and stays a draft" "$(cat "$T/state/releases.tsv")" "$(printf 'v0.2.0\ttrue')"
set_ptag v0.2.0 "$C1"

new_state ''
expect_fail "tag check: a lightweight tag is refused" "not an annotated tag" pub_tag v0.2.1 "$T/assets-0.2.1" "$C1" --notes-file "$GOODNOTES"
assert_lacks "tag check: ... nothing was created" "$(cat "$T/state.log")" "release create"
new_state ''
expect_fail "tag check: a tag that does not exist is refused" "missing or not an annotated tag" pub_tag v0.2.2 "$T/assets-0.2.2" "$C1" --notes-file "$GOODNOTES"
assert_lacks "tag check: ... nothing was created" "$(cat "$T/state.log")" "release create"
new_state ''
expect_fail "tag check: an unreachable remote is an error, not a pass" "cannot query" pub_tag v0.2.0 "$A" "$C1" --notes-file "$GOODNOTES" --remote "$T/does-not-exist.git"
assert_lacks "tag check: ... nothing was created" "$(cat "$T/state.log")" "release create"

# ================================================================================================
echo "== publish: existing assets (no blind --clobber)"
new_state 'v0.2.0\tfalse\tfalse\n'
seed_remote "$A"
expect_ok "assets: identical assets on a published release are left alone" "unchanged" pub_real
calls=$(cat "$T/state.log")
assert_lacks "assets: ... nothing uploaded" "$calls" "release upload"
assert_lacks "assets: ... nothing edited" "$calls" "release edit"

new_state 'v0.2.0\tfalse\tfalse\n'
seed_remote "$A"
printf 'a different build of the cli' >"$T/state/remote/lapis-net-cli-0.2.0.zip"
expect_fail "assets: a differing asset on a PUBLISHED release is refused" "refusing to replace published asset lapis-net-cli-0.2.0.zip" pub_real
calls=$(cat "$T/state.log")
assert_lacks "assets: ... never uploaded with --clobber" "$calls" "--clobber"
assert_lacks "assets: ... nothing uploaded at all" "$calls" "release upload"
assert_contains "assets: ... the published file is untouched" "$(cat "$T/state/remote/lapis-net-cli-0.2.0.zip")" "a different build of the cli"

new_state 'v0.2.0\ttrue\tfalse\n'
seed_remote "$A"
printf 'half of a zip' >"$T/state/remote/lapis-net-cli-0.2.0.zip"
expect_ok "assets: a differing asset on a DRAFT is replaced" "publishing leftover draft" pub_real
calls=$(cat "$T/state.log")
assert_contains "assets: ... with --clobber" "$calls" "release upload v0.2.0 --repo owner/name --clobber"
uploads=$(grep 'gh release upload' "$T/state.log" || true)
assert_lacks "assets: ... only the differing asset was uploaded" "$uploads" "lapis-net-browser-0.2.0.zip"
assert_contains "assets: ... and the draft was published" "$calls" "draft=false"
cmp -s "$T/state/remote/lapis-net-cli-0.2.0.zip" "$A/lapis-net-cli-0.2.0.zip" && ok "assets: ... the draft now holds the local build" || bad "assets: ... the draft now holds the local build"

new_state 'v0.2.0\tfalse\tfalse\n'
expect_ok "assets: a published release without assets is back-filled" "done" pub_real
calls=$(cat "$T/state.log")
assert_lacks "assets: ... without --clobber" "$calls" "--clobber"
c=$(grep -n 'upload.*SHA256SUMS' "$T/state.log" | head -n 1 | cut -d: -f1)
z=$(grep -n 'upload.*lapis-net-browser' "$T/state.log" | head -n 1 | cut -d: -f1)
if [[ -n "$c" && -n "$z" && "$z" -lt "$c" ]]; then ok "assets: ... SHA256SUMS is uploaded last"; else bad "assets: ... SHA256SUMS is uploaded last" "$z $c"; fi
assert_lacks "assets: ... a published release is not published again" "$calls" "draft=false"

new_state 'v0.2.0\tfalse\tfalse\n'
seed_remote "$A"
rm "$T/state/remote/lapis-net-browser-0.2.0.zip"
expect_ok "assets: only the missing asset is uploaded" "done" pub_real
calls=$(cat "$T/state.log")
assert_contains "assets: ... that one" "$calls" "release upload v0.2.0 --repo owner/name $A/lapis-net-browser-0.2.0.zip"
uploads=$(grep 'gh release upload' "$T/state.log" || true)
assert_lacks "assets: ... not the identical ones" "$uploads" "lapis-net-cli-0.2.0.zip"
assert_lacks "assets: ... never with --clobber" "$calls" "--clobber"

# ================================================================================================
echo "== real distributions"
if [[ -n "$DIST_CLI" ]]; then
  expect_ok "smoke test against the real ZIPs" "smoke test passed" "$S/smoke-test-dist.sh" --cli-zip "$DIST_CLI" --browser-zip "$DIST_BROWSER"
else
  skip "smoke test against the real ZIPs" "pass --with-dist <cli.zip> <browser.zip>"
fi

echo
echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
[[ $FAIL -eq 0 ]]
