#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/seladb/PcapPlusPlus.git'

pkgdir="${LOCAL_REPO_PATH}/PcapPlusPlus"
clone_or_update_git_repo "${URL}" "${pkgdir}"

cd "${pkgdir}"

distro_release="$(lsb_release -rs)"
if [ "$(lsb_release -is)" = 'CentOS' -a "${distro_release%%.*}" = '6' ]; then
    sed -i 's/\(PCAPPP_LIBS.*\)/\1 -lrt/'  mk/PcapPlusPlus.mk.linux
fi

yes 'no' | ./configure-linux.sh --install-dir "${PREFIX}"
make all install

cd "${SAVED_PWD}"
