#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/seladb/PcapPlusPlus.git'
#COMMIT='14a418ed4f9b72a832877dc8330e01259f617bf3'
#COMMIT='b55cd7dc29b8c41712752552095b883ed21f64a8'
#COMMIT='137fc51905f6598e6c796bf9ff7b622c1f51fd93'
COMMIT='747706bd9032bd4e8e7a90ba357d57d6bc2c4664'

pkgdir="${LOCAL_REPO_PATH}/PcapPlusPlus"
clone_or_update_git_repo "${URL}" "${pkgdir}" "${COMMIT}"

cd "${pkgdir}"

#yes 'no' | ./configure-linux.sh --install-dir "${PREFIX}"
#make all install

mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX} ..
make all install

cd "${SAVED_PWD}"
