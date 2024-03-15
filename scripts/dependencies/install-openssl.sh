#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://www.openssl.org/source/openssl-3.0.13.tar.gz'

cd "${LOCAL_REPO_PATH}"
wget "${URL}" -O- | tar -xzf-
cd openssl-3.0.13
./config --prefix=${PREFIX}
make
make install_sw

cd "${SAVED_PWD}"
