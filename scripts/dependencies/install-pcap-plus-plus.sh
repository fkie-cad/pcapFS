#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/seladb/PcapPlusPlus.git'
COMMIT='a49a79e0b67b402ad75ffa96c1795def36df75c8'


pkgdir="${LOCAL_REPO_PATH}/PcapPlusPlus"
clone_or_update_git_repo "${URL}" "${pkgdir}" "${COMMIT}"

cd "${pkgdir}"
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX} -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF ..
make all install

cd "${SAVED_PWD}"
