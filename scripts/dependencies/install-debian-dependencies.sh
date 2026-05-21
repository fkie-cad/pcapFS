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
    python3-venv
'
boost_pkgs='
    libboost-filesystem-dev
    libboost-iostreams-dev
    libboost-log-dev
    libboost-program-options-dev
    libboost-serialization-dev
'

if { [[ "${distro}" = 'Ubuntu' && "${release}" =~ ^(2[0-6]\.04|23\.10)$ ]]; } \
    || { [[ "${distro}" = 'Kali' ]]; } \
    || { [[ "${distro}" = 'Linuxmint' && "${release}" =~ ^2[1-2](\.[0-9])?$ ]]; } \
    || { [[ "${distro}" = 'Debian' && ( "${release}" = '11' || "${release}" = '12' || "${release}" = '13' ) ]]; }; then

    while sudo fuser /var/lib/apt/lists/lock; do
        sleep 1
    done
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ${common_pkgs}

    if [[ "${distro}" = 'Ubuntu' && "${release}" = '20.04' ]]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
        sudo pip3 install --upgrade meson cmake
        ${here}/install-boost.sh
        ${here}/install-openssl.sh
        ${here}/install-fuse.sh
    else
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
                    ${boost_pkgs} \
                    fuse3 \
                    libfuse3-dev

        if [[ "${distro}" = 'Debian' && "${release}" = '11' ]]; then
            # Bullseye ships CMake 3.18; pcapFS needs >= 3.21.
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip
            sudo pip3 install --upgrade cmake
            ${here}/install-openssl.sh
        else
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev
        fi
    fi

    ${here}/install-pcap-plus-plus-precompiled.sh
else
    echo "Unsupported release ${distro} ${release}." >&2
    exit 1
fi
