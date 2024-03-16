#!/usr/bin/env bash
set -eu

lsb_release="$(which lsb_release 2> /dev/null)"
if [[ -n "${lsb_release}" ]]; then
    distro="$(lsb_release -is)"
    if [[ "${distro}" = 'Fedora' ]]; then
        sudo dnf install -y catch2-devel
        exit 0
    elif [[ "${distro}" = 'Ubuntu' || "${distro}" = 'Kali' ]]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y catch2
        exit 0
    fi
fi

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/catchorg/Catch2.git'

pkgdir="${LOCAL_REPO_PATH}/Catch2"
clone_or_update_git_repo "${URL}" "${pkgdir}"

cd "${pkgdir}"
git checkout v2.x
cmake -Bbuild -H. -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX:PATH=${PREFIX}
cmake --build build --target install

cd "${SAVED_PWD}"
