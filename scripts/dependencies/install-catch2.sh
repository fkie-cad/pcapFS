#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/catchorg/Catch2.git'

pkgdir="${LOCAL_REPO_PATH}/Catch2"
clone_or_update_git_repo "${URL}" "${pkgdir}"

cd "${pkgdir}"
cmake -Bbuild -H. -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX}
cmake --build build --target install

cd "${SAVED_PWD}"
