#!/usr/bin/env bash
set -euo pipefail

lib_dir="${1:?library directory is required}"
lib_name="${2:?library name is required}"
archive_name="${3:?archive name is required}"
repo_root="${GITHUB_WORKSPACE:-$(pwd)}"

rm -f go-cross-bin.h "${lib_dir}/${PLUGIN_ID}.h"
cp -r rules "${lib_dir}/"

if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
	powershell -Command "Compress-Archive -Path '${lib_dir}/${lib_name}', '${lib_dir}/rules' -DestinationPath '${archive_name}'"
	certutil -hashfile "${archive_name}" SHA256 | grep -v "^SHA256" | sed "s/$/  ${archive_name}/" > "${archive_name}.sha256"
else
	(
		cd "${lib_dir}"
		zip -r "${repo_root}/${archive_name}" "${lib_name}" rules/
	)
	sha256sum "${archive_name}" > "${archive_name}.sha256"
fi
