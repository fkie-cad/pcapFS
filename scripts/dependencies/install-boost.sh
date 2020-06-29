#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

BOOST_MINOR_VERSION='69'
BOOST_VERSION="1_${BOOST_MINOR_VERSION}_0"

URL="https://dl.bintray.com/boostorg/release/1.${BOOST_MINOR_VERSION}.0/source/boost_${BOOST_VERSION}.tar.bz2"
BOOST_LIBS='filesystem,iostreams,log,system,serialization,program_options'

cd "${LOCAL_REPO_PATH}"
#wget "${URL}" -O- | tar -xjf-
if [ ! -f "boost_${BOOST_VERSION}.tar.bz2" ]; then
  wget "${URL}" -O "${DOWNLOADS}/boost_${BOOST_VERSION}.tar.bz2"
fi
tar -xjf "${DOWNLOADS}/boost_${BOOST_VERSION}.tar.bz2"
cd "boost_${BOOST_VERSION}"
./bootstrap.sh --with-libraries="${BOOST_LIBS}" --prefix=${PREFIX}
./b2 install

cd "${SAVED_PWD}"
