#!/usr/bin/env bash
# Creates or updates the GitHub release for a tag and attaches the release assets.
#   publish.sh --tag vX.Y.Z --assets-dir DIR --repo OWNER/NAME --expect-commit SHA [--remote R]
#              [--notes-file F] [--title S] [--dry-run --assume-exists yes|no]
#
# Environment: GH_TOKEN (required unless --dry-run), GH_BIN (default "gh"; the tests substitute a stub).
#
# --expect-commit is the full 40-hex commit the build job verified and built (needs.build.outputs.commit).
#   It is mandatory for a real run (fail closed). Before every call that changes the release the script
#   asks the remote (`git ls-remote R refs/tags/<tag>^{}`, R defaults to "origin") where the tag points
#   NOW and aborts if that is not the verified commit, so a tag that was force-moved between the build
#   and the publish never gets published. Restriction: `gh release create/edit` binds a release to the tag
#   NAME, and GitHub offers no way to bind it to a commit for an existing tag, so a move between the last
#   check and the GitHub call is narrowed to a few milliseconds, not excluded.
#
# Release does not exist yet:  --notes-file is mandatory and must be a real, non-trivial file in the
#   AsciiDoc/Markdown common subset. The release is created as a DRAFT with all assets, the uploaded
#   assets are downloaded again and their checksums verified, and only then the draft is published.
#   "Latest" is set explicitly: only if this tag is the highest published version.
# Release exists (published or draft): each expected asset is handled on its own - a missing one is
#   uploaded (without --clobber), one that is byte-identical (SHA-256) is left alone, one that differs
#   is replaced (--clobber) ONLY on a draft; on a published release a differing asset is an error,
#   because a download that was already verified must never change silently. SHA256SUMS goes last.
#   The title and text are NOT touched unless a notes file is given and exists - this is how a release
#   whose notes were written by hand (v0.10.0) is back-filled without losing them. A published
#   release never has its "Latest" marker changed; a leftover draft is published.
#
# With --dry-run, gh is never executed: every action is printed as "DRY-RUN: gh ...". Because nothing
# can be queried then, --assume-exists is mandatory. `git ls-remote` is the one exception: it is
# read-only, and it is executed when --expect-commit is given.
set -euo pipefail
umask 077
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GH_BIN="${GH_BIN:-gh}"

tag="" assets_dir="" repo="" notes_file="" title="" dry_run=false assume_exists="" expect_commit="" remote="origin"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2-}"; shift 2 ;;
    --assets-dir) assets_dir="${2-}"; shift 2 ;;
    --repo) repo="${2-}"; shift 2 ;;
    --notes-file) notes_file="${2-}"; shift 2 ;;
    --title) title="${2-}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --assume-exists) assume_exists="${2-}"; shift 2 ;;
    --expect-commit) expect_commit="${2-}"; shift 2 ;;
    --remote) remote="${2-}"; shift 2 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

is_valid_tag "$tag" || die "tag is not of the form vX.Y.Z"
[[ -d "$assets_dir" ]] || die "--assets-dir is not a directory"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must be OWNER/NAME"
[[ -n "$remote" ]] || die "--remote must not be empty"
if [[ -n "$expect_commit" ]]; then
  [[ "$expect_commit" =~ ^[0-9a-f]{40}$ ]] || die "--expect-commit must be a full 40-character lowercase hex commit"
fi
if $dry_run; then
  [[ "$assume_exists" == "yes" || "$assume_exists" == "no" ]] ||
    die "--dry-run cannot query GitHub: pass --assume-exists yes|no"
else
  [[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN is not set"
  [[ -n "$expect_commit" ]] || die "--expect-commit is required (the commit the build verified); refusing to publish without it"
  [[ -z "$assume_exists" ]] || die "--assume-exists is only valid together with --dry-run"
fi

# Title: one line, no control characters, bounded.
title=$(printf '%s' "$title" | LC_ALL=C tr -d '\000-\037\177')
title=${title:0:200}
[[ -n "$title" ]] || title="$tag"

version="${tag#v}"
zip_browser="lapis-net-browser-${version}.zip"
zip_cli="lapis-net-cli-${version}.zip"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/lapisnet-publish.XXXXXX")
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

# ---- 1. assets ---------------------------------------------------------------------------------
expected=$(printf '%s\n' "$zip_browser" "$zip_cli" SHA256SUMS | LC_ALL=C sort)
present=$(find "$assets_dir" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)
[[ "$present" == "$expected" ]] ||
  die "assets directory must contain exactly: $zip_browser $zip_cli SHA256SUMS"
"$SCRIPT_DIR/checksums.sh" verify "$assets_dir"

# ---- helpers -----------------------------------------------------------------------------------
gh_do() {
  if $dry_run; then
    printf 'DRY-RUN: gh'
    printf ' %q' "$@"
    printf '\n'
  else
    "$GH_BIN" "$@"
  fi
}

# verify_remote_tag: the tag on the remote must still be the annotated tag of the verified commit.
# `git ls-remote R refs/tags/<tag>^{}` prints the PEELED line (the commit the annotated tag points
# to) - lightweight and missing tags print nothing, which is an error here as well.
verify_remote_tag() {
  [[ -n "$expect_commit" ]] || return 0
  local out sha count
  out=$(git ls-remote "$remote" "refs/tags/${tag}^{}") || die "cannot query $remote for tag $tag"
  out=$(printf '%s\n' "$out" | awk -v r="refs/tags/${tag}^{}" '$2 == r { print $1 }')
  count=$(printf '%s\n' "$out" | grep -c . || true)
  [[ "$count" -eq 1 ]] ||
    die "tag $tag is missing or not an annotated tag on $remote (found $count peeled entries)"
  sha="$out"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "unexpected answer from $remote for tag $tag"
  [[ "$sha" == "$expect_commit" ]] ||
    die "tag $tag now points to $sha, the build verified $expect_commit - refusing to publish"
}

# gh_mutate: every call that changes the release is preceded by the tag check.
gh_mutate() {
  verify_remote_tag
  gh_do "$@"
}

# validate_notes <file>: a real text, and only constructs that render the same in AsciiDoc (the
# repository's documentation format) and in the Markdown that GitHub uses for release text.
validate_notes() {
  local f="$1" bytes nonspace bad
  [[ -f "$f" && -r "$f" ]] || die "release notes file not found: $f"
  bytes=$(wc -c <"$f" | tr -d ' ')
  [[ "$bytes" -le 100000 ]] || die "release notes are larger than 100000 bytes"
  nonspace=$(LC_ALL=C tr -d '[:space:]' <"$f" | wc -c | tr -d ' ')
  [[ "$nonspace" -ge 40 ]] || die "release notes $f are empty or too short (need at least 40 non-blank characters)"
  if LC_ALL=C grep -q $'[\001-\010\013\014\016-\037\177]' "$f"; then
    die "release notes $f contain control characters"
  fi
  bad=$(grep -nE '^(=|\[|----|\.\.\.\.|\|===|:[A-Za-z0-9_-]+:|include::|link:|xref:|image:)|(link|xref|image):[^[:space:]]*\[' "$f" | head -n 1 || true)
  [[ -z "$bad" ]] ||
    die "release notes use AsciiDoc-only syntax that GitHub would show as raw text (first at ${bad%%:*}); use paragraphs, '*' lists, \`code\`, **bold** and plain URLs only"
}

build_body() {
  local out="$1"
  {
    cat "$notes_file"
    printf '\n\n---\n\n'
    printf '**Downloads.** `%s` and `%s` need a JDK 25 on the PATH or in `JAVA_HOME`; unpack and run `bin/lapis-net-browser` or `bin/lapis-net-cli`. ' "$zip_browser" "$zip_cli"
    printf '`SHA256SUMS` lists the checksum of each file. The artifacts are **not signed**: the checksums only detect corrupted downloads, not a compromised release account. '
    printf 'See https://github.com/%s/blob/master/docs/releasing.adoc for how to verify them.\n' "$repo"
  } >"$out"
}

# ---- 2. does the release exist? ------------------------------------------------------------------
exists="" is_draft="false" highest=""
if $dry_run; then
  exists="$assume_exists"
else
  listing=$("$GH_BIN" release list --repo "$repo" --limit 200 --json tagName,isDraft,isPrerelease \
    --jq '.[] | [.tagName, .isDraft, .isPrerelease] | @tsv') || die "cannot list releases of $repo"
  exists="no"
  while IFS=$'\t' read -r t d p; do
    [[ -n "$t" ]] || continue
    if [[ "$t" == "$tag" ]]; then
      exists="yes"
      is_draft="$d"
      continue
    fi
    [[ "$d" == "false" && "$p" == "false" ]] || continue
    is_valid_tag "$t" || continue
    if [[ -z "$highest" ]] || semver_gt "$t" "$highest"; then
      highest="$t"
    fi
  done <<<"$listing"
fi

# "Latest" follows the creation time on GitHub, not the version number, so it is set explicitly.
latest_flag="--latest=false"
if $dry_run; then
  latest_flag="--latest=<decided at run time from 'gh release list'>"
elif [[ -z "$highest" ]] || semver_gt "$tag" "$highest"; then
  latest_flag="--latest=true"
fi

# verify_remote: download what is attached to the release and check the digests again.
verify_remote() {
  if $dry_run; then
    printf 'DRY-RUN: (would download the release assets again and verify SHA256SUMS)\n'
    return 0
  fi
  local dl="$TMP/verify" f name
  rm -rf "$dl"
  mkdir -p "$dl"
  "$GH_BIN" release download "$tag" --repo "$repo" --pattern '*' --dir "$dl" ||
    die "cannot download the assets of $tag for verification"
  for f in "$dl"/*; do
    name=$(basename "$f")
    case "$name" in
      "$zip_browser" | "$zip_cli" | SHA256SUMS) ;;
      *)
        log "WARNING: stale asset '$name' is attached to $tag; it is not removed automatically"
        rm -f "$f"
        ;;
    esac
  done
  "$SCRIPT_DIR/checksums.sh" verify "$dl"
  # what GitHub holds must be byte-identical to what this run built
  for name in "$zip_browser" "$zip_cli" SHA256SUMS; do
    cmp -s "$dl/$name" "$assets_dir/$name" || die "downloaded $name differs from the locally built one"
  done
}

# remote_asset_names: the names of the assets currently attached to the release, one per line.
remote_asset_names() {
  "$GH_BIN" release view "$tag" --repo "$repo" --json assets --jq '.assets[].name' ||
    die "cannot list the assets of release $tag"
}

# sync_assets: the asset policy for a release that already exists. Per expected asset:
#   missing on the release           -> upload it WITHOUT --clobber (GitHub refuses if it appeared meanwhile)
#   present and SHA-256-identical    -> leave it alone ("unchanged")
#   present but different, a DRAFT   -> replace it (--clobber); nothing was ever published
#   present but different, PUBLISHED -> error: a download that was already verified by someone must
#                                       never change silently. The distribution ZIPs are not guaranteed to be
#                                       byte-for-byte reproducible across machines, so a re-run on a
#                                       different runner after a successful publish can end here by
#                                       design; a half-uploaded asset has to be deleted by hand first.
# SHA256SUMS is handled last, so it never describes files that are not on the release yet.
sync_assets() {
  if $dry_run; then
    printf 'DRY-RUN: (would compare the assets already on the release by SHA-256; missing ones are uploaded without --clobber, identical ones are skipped, published assets are never replaced, differing assets of a draft are replaced with --clobber)\n'
    return 0
  fi
  local existing="$TMP/existing" present name local_sha remote_sha
  present=$(remote_asset_names) || exit 1
  rm -rf "$existing"
  mkdir -p "$existing"
  for name in "$zip_browser" "$zip_cli" SHA256SUMS; do
    if ! printf '%s\n' "$present" | grep -qxF -- "$name"; then
      log "uploading missing asset $name"
      gh_mutate release upload "$tag" --repo "$repo" "$assets_dir/$name"
      continue
    fi
    rm -f "$existing/$name"
    "$GH_BIN" release download "$tag" --repo "$repo" --pattern "$name" --dir "$existing" ||
      die "cannot download $name of $tag for comparison"
    [[ -f "$existing/$name" ]] || die "$name of $tag was not downloaded"
    local_sha=$(sha256_file "$assets_dir/$name")
    remote_sha=$(sha256_file "$existing/$name")
    if [[ "$local_sha" == "$remote_sha" ]]; then
      log "asset $name is unchanged"
    elif [[ "$is_draft" == "true" ]]; then
      log "asset $name differs from the local build; replacing it on the draft"
      gh_mutate release upload "$tag" --repo "$repo" --clobber "$assets_dir/$name"
    else
      die "refusing to replace published asset $name of $tag: it differs from the locally built file (local sha256 $local_sha, on the release $remote_sha). Published assets are never replaced; if it must be replaced, delete it from the release by hand first"
    fi
  done
}

# ---- 3. act ---------------------------------------------------------------------------------------
if [[ "$exists" == "no" ]]; then
  [[ -n "$notes_file" ]] || die "release $tag does not exist and no --notes-file was given (docs/release-notes/$tag.adoc is required)"
  validate_notes "$notes_file"
  build_body "$TMP/body.md"
  log "creating draft release $tag"
  gh_mutate release create "$tag" --repo "$repo" --verify-tag --draft --title "$title" \
    --notes-file "$TMP/body.md" \
    "$assets_dir/$zip_browser" "$assets_dir/$zip_cli" "$assets_dir/SHA256SUMS"
  verify_remote
  log "publishing $tag"
  gh_mutate release edit "$tag" --repo "$repo" --draft=false "$latest_flag"
else
  log "release $tag already exists (draft: $is_draft)"
  if [[ -n "$notes_file" && -f "$notes_file" ]]; then
    validate_notes "$notes_file"
    build_body "$TMP/body.md"
    gh_mutate release edit "$tag" --repo "$repo" --notes-file "$TMP/body.md"
  else
    log "no release notes file for $tag - keeping the existing title and notes"
  fi
  sync_assets
  verify_remote
  if [[ "$is_draft" == "true" ]]; then
    log "publishing leftover draft $tag"
    gh_mutate release edit "$tag" --repo "$repo" --draft=false "$latest_flag"
  fi
fi

if ! $dry_run; then
  "$GH_BIN" release list --repo "$repo" --limit 5 >&2 || true
fi
log "done"
