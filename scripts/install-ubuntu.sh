#!/usr/bin/env bash

set -Eeuo pipefail

readonly APP_NAME="agentless-monitoring"
readonly APP_USER="agentless-monitoring"
readonly APP_GROUP="agentless-monitoring"
readonly GO_VERSION="1.26.5"
readonly SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly STATE_DIR="/var/lib/${APP_NAME}"
readonly BINARY_PATH="/usr/local/bin/${APP_NAME}"
readonly SERVICE_PATH="/etc/systemd/system/${APP_NAME}.service"
readonly ENVIRONMENT_PATH="/etc/default/${APP_NAME}"

SKIP_PACKAGES=false
TEMP_DIR=""

cleanup() {
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

require_ubuntu() {
    [[ -r /etc/os-release ]] || fail "cannot identify the operating system"
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || fail "this installer supports Ubuntu only"
}

install_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git
}

install_go() {
    local deb_arch go_arch checksum archive download_url

    deb_arch="$(dpkg --print-architecture)"
    case "${deb_arch}" in
        amd64)
            go_arch="amd64"
            checksum="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
            ;;
        arm64)
            go_arch="arm64"
            checksum="fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49"
            ;;
        *)
            fail "unsupported Ubuntu architecture: ${deb_arch}"
            ;;
    esac

    if [[ -x /usr/local/go/bin/go ]] &&
        /usr/local/go/bin/go version | grep -q "go${GO_VERSION} "; then
        return
    fi

    archive="go${GO_VERSION}.linux-${go_arch}.tar.gz"
    download_url="https://go.dev/dl/${archive}"

    curl --fail --location --proto '=https' --tlsv1.2 \
        --output "${TEMP_DIR}/${archive}" "${download_url}"
    printf '%s  %s\n' "${checksum}" "${TEMP_DIR}/${archive}" | sha256sum --check --status \
        || fail "Go archive checksum verification failed"

    rm -rf -- /usr/local/go
    tar -C /usr/local -xzf "${TEMP_DIR}/${archive}"
    ln -sfn /usr/local/go/bin/go /usr/local/bin/go
    ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt
}

create_service_account() {
    if ! getent group "${APP_GROUP}" >/dev/null; then
        groupadd --system "${APP_GROUP}"
    fi
    if ! id -u "${APP_USER}" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "${APP_GROUP}" \
            --home-dir "${STATE_DIR}" \
            --shell /usr/sbin/nologin \
            "${APP_USER}"
    fi
    install -d -o "${APP_USER}" -g "${APP_GROUP}" -m 0750 "${STATE_DIR}"
}

build_application() {
    local version

    export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
    export CGO_ENABLED=0
    export GOTOOLCHAIN=local

    cd "${SOURCE_DIR}"
    go mod download
    go mod verify
    go test ./...

    version="$(git -c safe.directory="${SOURCE_DIR}" -C "${SOURCE_DIR}" rev-parse --short=12 HEAD)"
    go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${version}" \
        -o "${TEMP_DIR}/${APP_NAME}" \
        ./cmd/agentless-monitoring
}

install_application() {
    install -o root -g root -m 0755 \
        "${TEMP_DIR}/${APP_NAME}" "${BINARY_PATH}.new"
    mv -f -- "${BINARY_PATH}.new" "${BINARY_PATH}"

    install -o root -g root -m 0644 \
        "${SOURCE_DIR}/deploy/${APP_NAME}.service" "${SERVICE_PATH}"

    if [[ ! -e "${ENVIRONMENT_PATH}" ]]; then
        install -o root -g "${APP_GROUP}" -m 0640 \
            "${SOURCE_DIR}/deploy/${APP_NAME}.env" "${ENVIRONMENT_PATH}"
    fi
}

start_application() {
    local attempt

    systemctl daemon-reload
    systemctl enable "${APP_NAME}.service"
    systemctl restart "${APP_NAME}.service"

    for attempt in $(seq 1 20); do
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
    if [[ "${1:-}" == "--skip-packages" ]]; then
        SKIP_PACKAGES=true
        shift
    fi
    [[ "$#" -eq 0 ]] || fail "unknown argument: $1"

    require_root
    require_ubuntu
    TEMP_DIR="$(mktemp -d)"

    if [[ "${SKIP_PACKAGES}" != true ]]; then
        install_packages
    fi
    install_go
    create_service_account
    build_application
    install_application
    start_application

    printf '%s installed successfully\n' "${APP_NAME}"
}

main "$@"
