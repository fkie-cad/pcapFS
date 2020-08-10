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
    if [[ "${release}" = '14.04' ]]; then
        PYTHON_VERSION='3.6'
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
        sudo apt-get update
        sudo apt-get install -y \
                    g++-6 \
                    python${PYTHON_VERSION} \
                    python${PYTHON_VERSION}-dev \
                    python${PYTHON_VERSION}-venv
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-6 90
        python=$(which python${PYTHON_VERSION})
        sudo ${python} -m ensurepip
        pip=$(which pip${PYTHON_VERSION})
        sudo ${pip} install --upgrade pip
        sudo ${pip} install --upgrade \
            cmake \
            meson \
            ninja
        ${here}/install-boost.sh
    elif [[ "${release}" = '16.04' ]]; then
        sudo apt-get install -y \
                    ${boost_pkgs} \
                    python3-pip
        LC_ALL='C' pip3 install --upgrade \
            cmake \
            meson \
	    ninja
    elif [[ "${release}" = '18.04' || "${release}" = '20.04' || "${release}" =~ ^20[1,2][0-9]\.[0-9] ]]; then
        sudo apt-get install -y \
                    ${boost_pkgs} \
                    cmake \
                    meson \
                    ninja-build
    else
        echo "Unsupported Ubuntu release ${release}." >&2
        exit 2
    fi
    ${here}/install-cpptoml.sh
    ${here}/install-fuse.sh
    ${here}/install-fusepp.sh
    ${here}/install-json.sh
    ${here}/install-openssl.sh
    ${here}/install-pcap-plus-plus.sh
else
    echo 'This script is supposed to run on Ubuntu systems only.' >&2
    exit 3
fi
