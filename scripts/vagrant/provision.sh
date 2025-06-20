#!/usr/bin/env bash
set -u

mkdir pcapfs

(cd /vagrant && tar -cf - \
    --exclude=./3rdparty \
    --exclude=./build \
    --exclude=./dependencies \
    --exclude=./tests/system/venv \
    --exclude=./tests/crypto/venv \
    --exclude=.git \
    --exclude=.vscode \
    --exclude=.vagrant .) | tar -C pcapfs -xf -

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    distro="${ID}"
else
    echo "Cannot determine distribution. /etc/os-release not found." >&2
    exit 1
fi

if [[ "${distro}" = 'fedora' || "${distro}" = 'centos' ]]; then
    sudo dnf update -y
    sudo dnf install -y python3-pip
else
    # Kali had to roll a new signing key: https://www.kali.org/blog/new-kali-archive-signing-key/
    if [[ "${distro}" = 'kali' ]]; then
        sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
    fi

    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y python3-pip
    sudo DEBIAN_FRONTEND=noninteractive apt install -y python3-venv
fi
