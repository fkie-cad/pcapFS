#!/usr/bin/env bash
set -eu

SAVED_PWD="$(pwd -P)"
HERE=$(dirname $(readlink -e $0))
source "${HERE}/install-helpers.sh"

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"

if [[ "${distro}" = 'Ubuntu' ]]; then
    libdir='lib'
    if [[ "${release}" = '18.04' ]]; then
        package='pcapplusplus-23.09-ubuntu-18.04-gcc-7.5.0-x86_64'
    elif [[ "${release}" = '20.04' ]]; then
        package='pcapplusplus-23.09-ubuntu-20.04-gcc-9.4.0-x86_64'
    elif [[ "${release}" = '22.04' ]]; then
        package='pcapplusplus-23.09-ubuntu-22.04-gcc-11.2.0-x86_64'
    else
        ${HERE}/install-pcap-plus-plus.sh
        exit 0
    fi

elif [[ "${distro}" = 'CentOS' && "${release}" = '7' ]]; then
    libdir='lib64'
    package='pcapplusplus-23.09-centos-7-gcc-4.8.5-x86_64'

elif [[ "${distro}" = 'Fedora' && "${release}" = '37' ]]; then
    libdir='lib64'
    package='pcapplusplus-23.09-fedora-37-gcc-12.2.1-x86_64'

else
    ${HERE}/install-pcap-plus-plus.sh
    exit 0
fi

URL="https://github.com/seladb/PcapPlusPlus/releases/download/v23.09/${package}.tar.gz"

mkdir -p "${PREFIX}"/$libdir
cd "${PREFIX}"
wget "${URL}" -O- | tar -xzf-
sed -i "1s#.*#prefix=\"${PREFIX}\"#" $package/$libdir/pkgconfig/PcapPlusPlus.pc
cp -r $package/$libdir/* "${PREFIX}"/$libdir
cp -r $package/include/* "${PREFIX}"/include
rm -r $package
cd "${SAVED_PWD}"
