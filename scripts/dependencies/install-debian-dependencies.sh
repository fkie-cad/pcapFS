#!/usr/bin/env bash
set -eu

distro="$(lsb_release -is | tail -n 1)"
release="$(lsb_release -rs | tail -n 1)"
here=$(dirname $(readlink -e $0))

common_pkgs='
    build-essential
    git
    libpcap-dev
    pkg-config
    zlib1g-dev
    cmake
    ninja-build
'
boost_pkgs='
    libboost-filesystem-dev
    libboost-iostreams-dev
    libboost-log-dev
    libboost-program-options-dev
    libboost-system-dev
'

if { [[ "${distro}" = 'Ubuntu' && "${release}" =~ ^2[0-5]\.04|23\.10$ ]]; } \
    || { [[ "${distro}" = 'Kali' ]]; } \
    || { [[ "${distro}" = 'Linuxmint' && "${release}" =~ ^2[1-2](\.[0-3])?$ ]]; } \
    || { [[ "${distro}" = 'Debian' && ( "${release}" = '11' || "${release}" = '12' ) ]]; }; then

    while sudo fuser /var/lib/apt/lists/lock; do
        sleep 1
    done
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ${common_pkgs}

    if [[ "${distro}" = 'Ubuntu' && "${release}" = '20.04' ]]; then
        sudo pip3 install --upgrade meson
        ${here}/install-boost.sh
        ${here}/install-cpptoml.sh
        ${here}/install-openssl.sh
        ${here}/install-fuse.sh
    else
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
                    ${boost_pkgs} \
                    meson \
                    fuse3 \
                    libfuse3-dev

        if [[ "${distro}" = 'Debian' && "${release}" = '11' ]]; then
            ${here}/install-cpptoml.sh
            ${here}/install-openssl.sh
        else
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
                    libssl-dev \
                    libcpptoml-dev
        fi
    fi

    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    ${here}/install-pcap-plus-plus-precompiled.sh
else
    echo "Unsupported release ${distro} ${release}." >&2
    exit 1
fi
