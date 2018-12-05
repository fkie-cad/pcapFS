#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/openssl/openssl/archive/OpenSSL_1_1_1.tar.gz'

cd "${LOCAL_REPO_PATH}"
wget "${URL}" -O- | tar -xzf-
cd openssl-OpenSSL_1_1_1
./config --prefix=${PREFIX}
make
make install

cd "${SAVED_PWD}"
