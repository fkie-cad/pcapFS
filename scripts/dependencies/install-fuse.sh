#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/libfuse/libfuse.git'

pkgdir="${LOCAL_REPO_PATH}/libfuse"
clone_or_update_git_repo "${URL}" "${pkgdir}"

set +e
ninja="$(which ninja 2> /dev/null)"
if [ -z "${ninja}" ]; then
    ninja="$(which ninja-build)"
fi
set -e

cd "${pkgdir}"
mkdir -p 'build'
cd 'build' && rm -rf *
meson --prefix="${PREFIX}" ..
${ninja}
sudo ${ninja} install

uid="$(id -u)"
gid="$(id -g)"
sudo chown -R ${uid}:${gid} "${PREFIX}"
sudo chown root:root "${PREFIX}/bin/fusermount3"
sudo chmod 4711 "${PREFIX}/bin/fusermount3"

cd "${SAVED_PWD}"
