#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.bz2'
BOOST_LIBS='filesystem,iostreams,log,system,serialization,program_options'

cd "${LOCAL_REPO_PATH}"
wget "${URL}" -O- | tar -xjf-
cd boost_1_64_0
./bootstrap.sh --with-libraries="${BOOST_LIBS}" --prefix=${PREFIX}
./b2 install

cd "${SAVED_PWD}"
