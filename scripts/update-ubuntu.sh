#!/usr/bin/env bash

set -Eeuo pipefail

readonly APP_NAME="agentless-monitoring"
readonly SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || fail "run this script with sudo"
}

require_clean_main_branch() {
    local branch changes

    branch="$(git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" branch --show-current)"
    [[ "${branch}" == "main" ]] || fail "the source checkout must be on the main branch"

    changes="$(git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" status --porcelain)"
    [[ -z "${changes}" ]] || fail "the source checkout contains uncommitted changes"
}

update_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git
}

update_source() {
    git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" fetch --prune origin main
    git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" merge --ff-only origin/main
}

main() {
    [[ "$#" -eq 0 ]] || fail "this script does not accept arguments"
    require_root
    [[ -d "${SOURCE_DIR}/.git" ]] || fail "source repository not found at ${SOURCE_DIR}"
    require_clean_main_branch
    update_packages
    update_source

    exec "${SOURCE_DIR}/scripts/install-ubuntu.sh" --skip-packages
}

main "$@"
