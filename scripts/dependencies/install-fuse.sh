#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

pkgdir="fuse-3.16.2"

URL="https://github.com/libfuse/libfuse/releases/download/${pkgdir}/${pkgdir}.tar.gz"

wget "${URL}" -O- | tar -xzf-

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
