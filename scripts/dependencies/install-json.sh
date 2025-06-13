#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/nlohmann/json.git'
COMMIT='55f93686c01528224f448c19128836e7df245f72'

pkgdir="${LOCAL_REPO_PATH}/nlohmann_json"
clone_or_update_git_repo "${URL}" "${pkgdir}" "${COMMIT}"

cd "${pkgdir}"
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX} -DJSON_BuildTests=OFF ..
make
make install

cd "${SAVED_PWD}"
