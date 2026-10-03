#!/usr/bin/env bash
# Decides what a workflow run is going to do. Reads ONLY environment variables (the workflow sets
# them through `env:`, never by interpolating into the script):
#   EVENT_NAME     github.event_name
#   GIT_REF        github.ref
#   REF_NAME       github.ref_name
#   INPUT_TAG      workflow_dispatch input "tag"
#   INPUT_PUBLISH  workflow_dispatch input "publish" ("true"/"false")
# Outputs: mode (tag|snapshot), tag, publish (true|false).
set -euo pipefail
umask 077
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

event="${EVENT_NAME:-}"
ref="${GIT_REF:-}"
ref_name="${REF_NAME:-}"
input_tag="${INPUT_TAG:-}"
input_publish="${INPUT_PUBLISH:-}"

case "$event" in
  push)
    [[ "$ref" == "refs/tags/$ref_name" ]] || die "push event is not a tag push (ref is not refs/tags/<tag>)"
    is_valid_tag "$ref_name" || die "pushed tag is not of the form vX.Y.Z"
    set_output mode tag
    set_output tag "$ref_name"
    set_output publish true
    ;;
  workflow_dispatch)
    [[ "$ref" == "refs/heads/master" ]] || die "manual runs are only allowed from master"
    if [[ -z "$input_tag" ]]; then
      [[ "$input_publish" != "true" ]] || die "publish=true requires a tag"
      set_output mode snapshot
      set_output tag ""
      set_output publish false
    else
      is_valid_tag "$input_tag" || die "tag input is not of the form vX.Y.Z"
      set_output mode tag
      set_output tag "$input_tag"
      if [[ "$input_publish" == "true" ]]; then
        set_output publish true
      else
        set_output publish false
      fi
    fi
    ;;
  *)
    die "unsupported event '$event'"
    ;;
esac
