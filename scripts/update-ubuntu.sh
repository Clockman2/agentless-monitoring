#!/usr/bin/env bash

set -Eeuo pipefail

readonly APP_NAME="agentless-monitoring"
readonly APP_USER="agentless-monitoring"
readonly BUILD_USER="agentless-monitoring-build"
readonly BUILD_GROUP="agentless-monitoring-build"
readonly SOURCE_DIR="/opt/agentless-monitoring-src"
readonly BINARY_PATH="/usr/local/bin/${APP_NAME}"
readonly UPDATER_PATH="/usr/local/sbin/${APP_NAME}-update"
readonly EXPECTED_REMOTE_HTTPS="https://github.com/Clockman2/agentless-monitoring.git"
readonly EXPECTED_REMOTE_SSH="git@github.com:Clockman2/agentless-monitoring.git"

TEMP_DIR=""
WORKTREE_DIR=""
COMMIT=""

cleanup() {
	if [[ -n "${WORKTREE_DIR}" && -d "${WORKTREE_DIR}" ]]; then
		git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" worktree remove --force "${WORKTREE_DIR}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
		rm -rf -- "${TEMP_DIR}"
	fi
}
trap cleanup EXIT

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

require_root() {
	[[ "${EUID}" -eq 0 ]] || fail "run this script with sudo"
}

parse_arguments() {
	while [[ "$#" -gt 0 ]]; do
		case "$1" in
			--commit)
				[[ "$#" -ge 2 ]] || fail "--commit requires a full Git commit SHA"
				COMMIT="$2"
				shift 2
				;;
			*)
				fail "unknown argument: $1"
				;;
		esac
	done
	[[ "${COMMIT}" =~ ^[0-9a-f]{40}$ ]] || fail "--commit must be a full lowercase 40-character Git SHA"
}

require_source_repository() {
	local remote changes

	[[ -d "${SOURCE_DIR}/.git" ]] || fail "source repository not found at ${SOURCE_DIR}"
	changes="$(git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" status --porcelain)"
	[[ -z "${changes}" ]] || fail "the source checkout contains uncommitted changes"
	remote="$(git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" remote get-url origin)"
	if [[ "${remote}" != "${EXPECTED_REMOTE_HTTPS}" && "${remote}" != "${EXPECTED_REMOTE_SSH}" ]]; then
		fail "origin does not match the expected GitHub repository"
	fi
	id -u "${APP_USER}" >/dev/null 2>&1 || fail "service account ${APP_USER} does not exist"
	id -u "${BUILD_USER}" >/dev/null 2>&1 || fail "build account ${BUILD_USER} does not exist"
	getent group "${BUILD_GROUP}" >/dev/null || fail "build group ${BUILD_GROUP} does not exist"
}

update_packages() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends ca-certificates curl git
}

prepare_source() {
	git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" fetch --no-tags \
		origin main:refs/remotes/origin/main
	git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" cat-file -e "${COMMIT}^{commit}" \
		|| fail "requested commit was not fetched from origin"
	git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" merge-base --is-ancestor "${COMMIT}" origin/main \
		|| fail "requested commit is not contained in origin/main"

	WORKTREE_DIR="${TEMP_DIR}/source"
	git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" worktree add --detach "${WORKTREE_DIR}" "${COMMIT}"
}

run_go_as_builder() {
	runuser --user "${BUILD_USER}" -- env \
		HOME="${TEMP_DIR}/home" \
		PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin" \
		CGO_ENABLED=0 \
		GOTOOLCHAIN=local \
		GOCACHE="${TEMP_DIR}/go-build" \
		GOMODCACHE="${TEMP_DIR}/go-mod" \
		go -C "${WORKTREE_DIR}" "$@"
}

build_application() {
	local version

	version="$(git -c safe.directory="${WORKTREE_DIR}" -C "${WORKTREE_DIR}" rev-parse --short=12 HEAD)"
	chmod 0711 "${TEMP_DIR}"
	install -d -o "${BUILD_USER}" -g "${BUILD_GROUP}" -m 0700 \
		"${TEMP_DIR}/home" "${TEMP_DIR}/go-build" "${TEMP_DIR}/go-mod" "${TEMP_DIR}/output"

	run_go_as_builder mod download
	run_go_as_builder mod verify
	run_go_as_builder test -buildvcs=false ./...
	run_go_as_builder build \
		-buildvcs=false \
		-trimpath \
		-ldflags "-s -w -X main.version=${version}" \
		-o "${TEMP_DIR}/output/${APP_NAME}" \
		./cmd/agentless-monitoring
}

install_and_restart() {
	install -o root -g root -m 0755 "${TEMP_DIR}/output/${APP_NAME}" "${BINARY_PATH}.new"
	mv -f -- "${BINARY_PATH}.new" "${BINARY_PATH}"
	install -o root -g root -m 0755 "${WORKTREE_DIR}/scripts/update-ubuntu.sh" "${UPDATER_PATH}.new"
	mv -f -- "${UPDATER_PATH}.new" "${UPDATER_PATH}"
	systemctl restart "${APP_NAME}.service"

	for _ in $(seq 1 20); do
		if curl --fail --silent --show-error \
			"${HEALTH_URL:-http://127.0.0.1:8080/healthz}"; then
			printf '\n'
			return
		fi
		sleep 1
	done
	systemctl status "${APP_NAME}.service" --no-pager || true
	fail "application health check did not succeed"
}

main() {
	require_root
	parse_arguments "$@"
	require_source_repository
	TEMP_DIR="$(mktemp -d)"
	update_packages
	prepare_source
	build_application
	install_and_restart
	printf '%s updated to %s\n' "${APP_NAME}" "${COMMIT}"
}

main "$@"
