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
    fuse3
    fuse3-devel
    git
    libpcap-devel
    perl-File-Compare
    perl-File-Copy
    perl-FindBin
    perl-Pod-Html
    perl-IPC-Cmd
    zlib-devel
    openssl-devel
'

if [ "${distro}" = 'Fedora' ]; then
    if [[ "${release_major}" =~ ^3[7-9]|40 ]]; then
        sudo dnf install -y ${common_pkgs}
        if [[ "${release_major}" =~ ^3[7-9] ]]; then
            sudo dnf install -y cpptoml-devel
        else
            sudo dnf install -y patch
            ${here}/install-cpptoml.sh
        fi

    else
        echo "Unsupported Fedora release ${release}." >&2
        exit 2
    fi
    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    if [ "${release_major}" = '37' ]; then
        ${here}/install-pcap-plus-plus-precompiled.sh
    else
        ${here}/install-pcap-plus-plus.sh
    fi
else
    echo 'This script is supposed to run on Fedora systems only.' >&2
    exit 3
fi
