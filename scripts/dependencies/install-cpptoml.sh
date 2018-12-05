#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/skystrife/cpptoml.git'

pkgdir="${LOCAL_REPO_PATH}/cpptoml"
clone_or_update_git_repo "${URL}" "${pkgdir}"

cd "${pkgdir}"
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX} ..
make
make install

cd "${SAVED_PWD}"
