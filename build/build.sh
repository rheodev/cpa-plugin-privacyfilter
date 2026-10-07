#!/usr/bin/env bash
# Builds the plugin shared library for linux/amd64 inside a golang:1.26-bookworm
# container, so the result is linked against Debian bookworm's glibc (2.36) and
# loads inside the debian:bookworm-slim image that runs CLIProxyAPI on the
# target host. Building natively on Fedora would link against a newer glibc and
# fail at dlopen time, not at compile time.
#
# Podman is used rootless: root inside the container maps to the invoking user,
# so the output file is owned by the user without any chown. ":Z" relabels the
# mounted source tree for the container under SELinux enforcing mode. Module and
# build caches live in named volumes so repeated builds do not re-download.
#
# Usage:  build/build.sh [VERSION]
# Output: dist/privacyfilter.so (the companion .h header is removed) and
#         dist/machine-ids.py, the term-list helper that ships next to it
set -euo pipefail

VERSION="${1:-${VERSION:-0.4.0-dev}}"
IMAGE="${IMAGE:-docker.io/library/golang:1.26-bookworm}"
PLUGIN_NAME="${PLUGIN_NAME:-privacyfilter}"
BUILD_TAGS="${BUILD_TAGS:-}"           # e.g. "betterleaks"
TARGET_GLIBC_MAX="${TARGET_GLIBC_MAX:-2.36}"   # glibc of debian:bookworm-slim

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/dist"
mkdir -p "${OUT_DIR}"

TAG_FLAG=""
if [[ -n "${BUILD_TAGS}" ]]; then
	TAG_FLAG="-tags ${BUILD_TAGS}"
fi

echo "==> building ${PLUGIN_NAME}.so version ${VERSION} in ${IMAGE}"
podman run --rm \
	-v "${REPO_ROOT}:/src:Z" \
	-v cpa-privacyfilter-gomod:/go/pkg/mod \
	-v cpa-privacyfilter-gocache:/root/.cache/go-build \
	-w /src \
	-e CGO_ENABLED=1 -e GOOS=linux -e GOARCH=amd64 -e GOFLAGS=-mod=mod \
	"${IMAGE}" \
	sh -euc "
		go build -trimpath -buildmode=c-shared ${TAG_FLAG} \
			-ldflags '-s -w -X main.pluginVersion=${VERSION}' \
			-o dist/${PLUGIN_NAME}.so . &&
		rm -f dist/${PLUGIN_NAME}.h &&
		echo '==> glibc symbol versions required by the result:' &&
		objdump -T dist/${PLUGIN_NAME}.so | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tr '\n' ' ' && echo &&
		max=\$(objdump -T dist/${PLUGIN_NAME}.so | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1) &&
		echo \"==> highest required glibc: \${max} (target allows up to ${TARGET_GLIBC_MAX})\" &&
		test \"\$(printf '%s\n%s\n' \"\${max}\" '${TARGET_GLIBC_MAX}' | sort -V | tail -1)\" = '${TARGET_GLIBC_MAX}'
	"

install -m 0755 "${REPO_ROOT}/tools/machine-ids.py" "${OUT_DIR}/machine-ids.py"
ls -l "${OUT_DIR}/${PLUGIN_NAME}.so" "${OUT_DIR}/machine-ids.py"
echo "==> ok: ${OUT_DIR}/${PLUGIN_NAME}.so"
