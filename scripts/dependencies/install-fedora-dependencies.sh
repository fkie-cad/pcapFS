#!/usr/bin/env bash
set -eu

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"
here=$(dirname $(readlink -e $0))

release_major=${release%%.*}

common_pkgs='
    boost-devel
    boost-filesystem
    boost-iostreams
    boost-log
    gcc-c++
    cmake
    cpptoml-devel
    fuse3
    fuse3-devel
    git
    libpcap-devel
    perl-File-Compare
    perl-File-Copy
    perl-FindBin
    perl-Pod-Html
    zlib-devel
'

if [ "${distro}" = 'Fedora' ]; then
    if [ "${release_major}" = '38' ]; then
        sudo dnf install -y ${common_pkgs}
    else
        echo "Unsupported Fedora release ${release}." >&2
        exit 2
    fi
    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    ${here}/install-openssl.sh
    ${here}/install-pcap-plus-plus.sh
else
    echo 'This script is supposed to run on Fedora systems only.' >&2
    exit 3
fi
