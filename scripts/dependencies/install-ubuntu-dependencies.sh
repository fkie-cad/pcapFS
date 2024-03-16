#!/usr/bin/env bash
set -eu

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"
here=$(dirname $(readlink -e $0))

common_pkgs='
    build-essential
    git
    libpcap-dev
    pkg-config
    zlib1g-dev
'
boost_pkgs='
    libboost-filesystem-dev
    libboost-iostreams-dev
    libboost-log-dev
    libboost-program-options-dev
    libboost-system-dev
'

if [[ "${distro}" = 'Ubuntu' || "${distro}" = 'Kali' ]]; then
    while sudo fuser /var/lib/apt/lists/lock; do
        sleep 1
    done
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ${common_pkgs}
    if [[ "${release}" = '18.04' ]]; then
        sudo apt-get install -y \
                    cmake \
                    ninja-build \
                    python3-pip
        LC_ALL='C' pip3 install --upgrade meson
        . ~/.profile
        ${here}/install-boost.sh
        ${here}/install-cpptoml.sh
        ${here}/install-openssl.sh
        ${here}/install-fuse.sh
    elif [[ "${release}" =~ ^2[0-2]\.04 || "${release}" =~ ^20[1,2][0-9]\.[0-9] ]]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
                    ${boost_pkgs} \
                    cmake \
                    meson \
                    ninja-build
        if [[ "${release}" = '22.04'|| "${distro}" = 'Kali' ]]; then
            sudo DEBIAN_FRONTEND=noninteractive apt install -y \
                    fuse3 \
                    libfuse3-dev \
                    libssl-dev \
                    libcpptoml-dev
        else
            # openssl and fuse package are not the required version 3 -> need to build from source
            ${here}/install-cpptoml.sh
            ${here}/install-openssl.sh
            ${here}/install-fuse.sh
        fi
    else
        echo "Unsupported Ubuntu release ${release}." >&2
        exit 2
    fi

    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    ${here}/install-pcap-plus-plus-precompiled.sh
else
    echo 'This script is supposed to run on Ubuntu systems only.' >&2
    exit 3
fi
