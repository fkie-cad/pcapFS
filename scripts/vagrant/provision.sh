#!/usr/bin/env bash
set -u

mkdir pcapfs

(cd /vagrant && tar -cf - \
    --exclude=./3rdparty \
    --exclude=./build \
    --exclude=./cmake-build-debug \
    --exclude=./dependencies \
    --exclude=.git \
    --exclude=.vagrant .) | tar -C pcapfs -xf -

if [[ -f '/etc/fedora-release' ]]; then
    sudo dnf install -y lsb_release python3-virtualenv
fi

distro="$(lsb_release -is)"
release="$(lsb_release -rs)"

if [[ "${distro}" = 'Ubuntu' || "${distro}" = 'Kali' ]]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    if [[ "${distro}" = 'Ubuntu' && "${distro}" = 1* ]]; then
        virtualenv_pkg='python-virtualenv'
    else
        virtualenv_pkg='virtualenv'
    fi
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${virtualenv_pkg}"
elif [[ "${distro}" = 'CentOS' ]]; then
    sudo yum install -y python-virtualenv
fi
