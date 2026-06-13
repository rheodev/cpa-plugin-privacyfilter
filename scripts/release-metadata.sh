#!/usr/bin/env bash
set -euo pipefail

goos="${1:?goos is required}"
goarch="${2:?goarch is required}"
ext="${3:-}"

if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" == v* ]]; then
	version="${GITHUB_REF_NAME#v}"
else
	version="0.0.0-dev"
fi

archive_name="${PLUGIN_ID}_${version}_${goos}_${goarch}.zip"

{
	echo "VERSION=${version}"
	echo "ARCHIVE_NAME=${archive_name}"
	if [[ -n "${ext}" ]]; then
		echo "LIB_NAME=${PLUGIN_ID}.${ext}"
	fi
} >> "${GITHUB_ENV}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
	echo "version=${version}" >> "${GITHUB_OUTPUT}"
fi
