#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"

if [[ "${distro}" = 'Ubuntu' ]]; then
    libdir='lib'
    if [[ "${release}" = '20.04' ]]; then
        package='pcapplusplus-25.05-ubuntu-20.04-gcc-9.4.0-x86_64'
    elif [[ "${release}" = '22.04' ]]; then
        package='pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64'
    elif [[ "${release}" = '24.04' ]]; then
        package='pcapplusplus-25.05-ubuntu-24.04-gcc-13.3.0-x86_64'
    else
        ${HERE}/install-pcap-plus-plus.sh
        exit 0
    fi

elif [[ "${distro}" = 'Fedora' && "${release}" = '42' ]]; then
    libdir='lib64'
    package='pcapplusplus-25.05-fedora-42-gcc-15.0.1-x86_64'

else
    ${HERE}/install-pcap-plus-plus.sh
    exit 0
fi

URL="https://github.com/seladb/PcapPlusPlus/releases/download/v25.05/${package}.tar.gz"

mkdir -p "${PREFIX}"/$libdir
cd "${PREFIX}"
wget "${URL}" -O- | tar -xzf-
sed -i "1s#.*#prefix=\"${PREFIX}\"#" $package/$libdir/pkgconfig/PcapPlusPlus.pc
cp -r $package/$libdir/* "${PREFIX}"/$libdir
cp -r $package/include/* "${PREFIX}"/include
rm -r $package
cd "${SAVED_PWD}"
