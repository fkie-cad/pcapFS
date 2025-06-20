#!/usr/bin/env bash
set -eu

here=$(dirname $(readlink -e $0))

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    distro="${ID}"
    release="${VERSION_ID}"
else
    echo "Cannot determine distribution. /etc/os-release not found." >&2
    exit 1
fi

common_pkgs='
    boost-devel
    boost-filesystem
    boost-iostreams
    boost-log
    gcc-c++
    cmake
    fuse3
    fuse3-devel
    bzip2-devel
    xz-devel
    libzstd-devel
    git
    libpcap-devel
    zlib-devel
    openssl-devel
    patch
'

if [ "${distro}" = 'centos' ]; then
    if [[ "${release}" = '9' || "${release}" = '10' ]]; then
        sudo dnf update -y
        # libpcap-devel requires crb
        sudo dnf config-manager --set-enabled crb
        sudo dnf install -y ${common_pkgs}
        sudo dnf config-manager --set-disabled crb
        ${here}/install-fusepp.sh
        ${here}/install-json.sh
        ${here}/install-cpptoml.sh
        ${here}/install-pcap-plus-plus.sh
    else
        echo "Unsupported CentOS release ${release}." >&2
        exit 2
    fi
else
    echo 'This script is supposed to run on CentOS systems only.' >&2
    exit 3
fi
