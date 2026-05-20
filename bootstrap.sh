#!/usr/bin/env bash
#
# One-command end-to-end build for pcapFS.
#
#   ./bootstrap.sh              # install deps, configure, build
#   ./bootstrap.sh --install    # ... + sudo cmake --install build
#   ./bootstrap.sh --tests      # ... + run crypto and system pytest suites
#   ./bootstrap.sh --jobs N     # parallel build jobs (default: nproc)
#   ./bootstrap.sh --skip-deps  # skip the dependency-install step
#
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

do_install=0
do_tests=0
skip_deps=0
jobs="$(nproc 2>/dev/null || echo 2)"
build_dir="${here}/build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install)    do_install=1 ;;
        --tests)      do_tests=1 ;;
        --skip-deps)  skip_deps=1 ;;
        --jobs)       jobs="$2"; shift ;;
        --jobs=*)     jobs="${1#--jobs=}" ;;
        -h|--help)
            sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

if [[ "${skip_deps}" -eq 0 ]]; then
    "${here}/scripts/dependencies/install-all-dependencies.sh"
fi

cmake -S "${here}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" -j "${jobs}"

if [[ "${do_install}" -eq 1 ]]; then
    sudo cmake --install "${build_dir}"
fi

if [[ "${do_tests}" -eq 1 ]]; then
    "${here}/tests/crypto/run-crypto-tests.sh"
    "${here}/tests/system/run-system-tests.sh"
fi
