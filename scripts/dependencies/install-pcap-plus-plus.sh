#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/seladb/PcapPlusPlus.git'
#COMMIT='14a418ed4f9b72a832877dc8330e01259f617bf3'
COMMIT='b55cd7dc29b8c41712752552095b883ed21f64a8'

pkgdir="${LOCAL_REPO_PATH}/PcapPlusPlus"
clone_or_update_git_repo "${URL}" "${pkgdir}" "${COMMIT}"

cd "${pkgdir}"

yes 'no' | ./configure-linux.sh --install-dir "${PREFIX}"
make all install

cd "${SAVED_PWD}"
