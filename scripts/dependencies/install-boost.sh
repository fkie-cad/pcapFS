#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

BOOST_MINOR_VERSION='77'
BOOST_VERSION="1_${BOOST_MINOR_VERSION}_0"

#URL="https://dl.bintray.com/boostorg/release/1.${BOOST_MINOR_VERSION}.0/source/boost_${BOOST_VERSION}.tar.bz2"
#URL="https://boostorg.jfrog.io/artifactory/main/release/1.${BOOST_MINOR_VERSION}.0/source/boost_${BOOST_VERSION}.tar.bz2"
URL="https://archives.boost.io/release/1.${BOOST_MINOR_VERSION}.0/source/boost_${BOOST_VERSION}.tar.bz2"
BOOST_LIBS='filesystem,iostreams,log,regex,system,serialization,program_options'

cd "${LOCAL_REPO_PATH}"
#wget "${URL}" -O- | tar -xjf-
if [ ! -f "boost_${BOOST_VERSION}.tar.bz2" ]; then
  wget "${URL}" -O "${PREFIX}/boost_${BOOST_VERSION}.tar.bz2"
fi
tar -xjf "${PREFIX}/boost_${BOOST_VERSION}.tar.bz2"
cd "boost_${BOOST_VERSION}"
./bootstrap.sh --with-libraries="${BOOST_LIBS}" --prefix=${PREFIX} --without-icu
./b2 install

cd "${SAVED_PWD}"
