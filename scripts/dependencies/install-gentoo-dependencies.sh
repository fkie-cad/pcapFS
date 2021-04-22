#!/usr/bin/env bash
set -eu

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"
here=$(dirname $(readlink -e $0))

if [[ "${distro}" = 'Gentoo' ]]; then

#    sudo emerge -av \
#        cmake \
#        meson \
#        ninja \
#        git \
#        libpcap \
#        zlib \
#        fuse \
#        lsb-release

    ${here}/install-boost.sh
    ${here}/install-cpptoml.sh
    ${here}/install-gentoo-fuse.sh
    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    ${here}/install-openssl.sh
    ${here}/install-pcap-plus-plus.sh
    ${here}/install-catch2.sh
else
    echo 'This script is supposed to run on Gentoo systems only.' >&2
    exit 3
fi
