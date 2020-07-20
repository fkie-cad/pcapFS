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
    libpcap-devel
    python36-devel
    zlib-devel
'
    #json-devel

pip_pkgs='
    cmake
    meson
    ninja
'

enable_devtoolset='scl enable devtoolset-7'


if [ "${distro}" = 'CentOS' ]; then
    if [ "${release_major}" = '7' ]; then
        sudo yum install -y \
            https://centos${release_major}.iuscommunity.org/ius-release.rpm \
            centos-release-scl
        sudo yum update -y
        sudo yum install -y ${common_pkgs}
        sudo pip3 install --upgrade ${pip_pkgs}
    else
        echo "Unsupported CentOS release ${release}." >&2
        exit 2
    fi
    ${enable_devtoolset} ${here}/install-boost.sh
    ${enable_devtoolset} ${here}/install-cpptoml.sh
    ${enable_devtoolset} ${here}/install-fuse.sh
    ${enable_devtoolset} ${here}/install-fusepp.sh
    ${enable_devtoolset} ${here}/install-json.sh
    ${enable_devtoolset} ${here}/install-openssl.sh
    ${enable_devtoolset} ${here}/install-pcap-plus-plus.sh
else
    echo 'This script is supposed to run on CentOS systems only.' >&2
    exit 3
fi
