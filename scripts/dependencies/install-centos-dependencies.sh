#!/usr/bin/env bash
set -eu

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"
here=$(dirname $(readlink -e $0))

release_major=${release%%.*}

common_pkgs='
    gcc-c++
    devtoolset-7-gcc-c++
    git
    json-devel
    libpcap-devel
    ninja-build
    python36u-devel
    python36u-pip
    zlib-devel
'

pip_pkgs='
    cmake
    meson
'

enable_devtoolset=''


if [ "${distro}" = 'CentOS' ]; then
    if [ "${release_major}" = '7' ]; then
        sudo yum install -y \
            https://centos${release_major}.iuscommunity.org/ius-release.rpm \
            centos-release-scl
        sudo yum update -y
        sudo yum install -y ${common_pkgs}
        sudo pip3.6 install --upgrade ${pip_pkgs}
    else
        echo "Unsupported CentOS release ${release}." >&2
        exit 2
    fi
    ${here}/install-boost.sh
    ${here}/install-cpptoml.sh
    ${here}/install-fuse.sh
    ${here}/install-fusepp.sh
    ${here}/install-openssl.sh
    ${here}/install-pcap-plus-plus.sh
else
    echo 'This script is supposed to run on CentOS systems only.' >&2
    exit 3
fi
