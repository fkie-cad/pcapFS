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
    if [ "${release_major}" = '6' ]; then
        enable_devtoolset='scl enable devtoolset-7'
        common_pkgs="${common_pkgs} libudev-devel"
        pip_pkgs="${pip_pkgs} ninja"
    elif [ "${release_major}" = '7' ]; then
        common_pkgs="${common_pkgs} json-devel"
    fi
    if [ "${release_major}" = '6' -o "${release_major}" = '7' ]; then
    sudo yum install -y \
            https://centos${release_major}.iuscommunity.org/ius-release.rpm \
            centos-release-scl
    sudo yum update -y
    sudo yum install -y ${common_pkgs}
    pip="$(which pip3.6)"
    sudo ${pip} install --upgrade ${pip_pkgs}
    ${here}/install-boost.sh
    else
        echo "Unsupported CentOS release ${release}." >&2
        exit 2
    fi
    ${enable_devtoolset} ${here}/install-cpptoml.sh
    ${enable_devtoolset} ${here}/install-fuse.sh
    ${enable_devtoolset} ${here}/install-fusepp.sh
    ${enable_devtoolset} ${here}/install-json.sh
    ${enable_devtoolset} ${here}/install-openssl.sh
    if [ "${release_major}" = '6' ]; then
        ${enable_devtoolset} ${here}/install-pcap-plus-plus.sh
    else
        ${enable_devtoolset} ${here}/install-pcap-plus-plus-precompiled.sh
    fi
else
    echo 'This script is supposed to run on CentOS systems only.' >&2
    exit 3
fi
