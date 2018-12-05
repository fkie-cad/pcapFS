#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

URL='https://github.com/jachappell/Fusepp.git'

pkgdir="${LOCAL_REPO_PATH}/Fusepp"
clone_or_update_git_repo "${URL}" "${pkgdir}"

mkdir -p "${PREFIX}/include/Fusepp"
cd "${pkgdir}"
install Fuse.cpp Fuse.h Fuse-impl.h "${PREFIX}/include/Fusepp"

cd "${SAVED_PWD}"
