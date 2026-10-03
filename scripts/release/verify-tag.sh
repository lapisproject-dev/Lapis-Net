#!/usr/bin/env bash
# Verifies that a release tag is acceptable:
#   verify-tag.sh --tag vX.Y.Z [--master-ref refs/remotes/origin/master] [--repo-dir .]
# Checks, in order: format, existence (full ref name, so a same-named branch cannot shadow it),
# annotated (not lightweight), commit is reachable from master, build.gradle.kts version at that
# commit equals the tag. Prints version, commit and title (the annotation's first line).
set -euo pipefail
umask 077
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

tag="" master_ref="refs/remotes/origin/master" repo_dir="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2-}"; shift 2 ;;
    --master-ref) master_ref="${2-}"; shift 2 ;;
    --repo-dir) repo_dir="${2-}"; shift 2 ;;
    *) die "unknown argument '$1'" ;;
  esac
done

[[ -n "$tag" ]] || die "--tag is required"
is_valid_tag "$tag" || die "tag is not of the form vX.Y.Z"
cd "$repo_dir"

tag_ref="refs/tags/$tag"
git rev-parse --verify --quiet "$tag_ref" >/dev/null || die "tag $tag does not exist"

objtype=$(git cat-file -t "$tag_ref")
[[ "$objtype" == "tag" ]] ||
  die "$tag is a lightweight tag - re-create it with: git tag -a $tag -m \"...\""

commit=$(git rev-parse --verify "${tag_ref}^{commit}")
git rev-parse --verify --quiet "$master_ref" >/dev/null || die "master ref $master_ref not found"
git merge-base --is-ancestor "$commit" "$master_ref" ||
  die "tag commit $commit is not on master ($master_ref)"

version=$(project_version_from "$commit")
[[ "$version" == "${tag#v}" ]] ||
  die "tag is $tag but build.gradle.kts at $commit declares version $version (the version is hard-coded and must be bumped before tagging)"

title=$(git for-each-ref "$tag_ref" --format='%(contents:subject)' | LC_ALL=C tr -d '\000-\037\177')
title=${title#"${title%%[![:space:]]*}"}
title=${title%"${title##*[![:space:]]}"}
[[ -n "$title" ]] || title="$tag"

set_output version "$version"
set_output commit "$commit"
set_output title "$title"
