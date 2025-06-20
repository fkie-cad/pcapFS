#!/usr/bin/env bash
set -eu

saved_pwd="$(pwd -P)"

function determine_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
        return
    fi
    echo "unknown"
}

distro="$(determine_distro)"

install_dependencies=''
if [[ "${distro}" = 'ubuntu' || "${distro}" = 'kali' || "${distro}" = 'linuxmint' || "${distro}" = 'debian' ]]; then
    install_dependencies='install-debian-dependencies.sh'
elif [[ "${distro}" = 'centos' ]]; then
    install_dependencies='install-centos-dependencies.sh'
elif [[ "${distro}" = 'fedora' ]]; then
    sudo dnf install -y lsb_release
    install_dependencies='install-fedora-dependencies.sh'
else
    echo 'Your distribution is not yet supported by this script.' >&2
    exit 1
fi

here=$(dirname $(readlink -e $0))
${here}/${install_dependencies}

cd "${saved_pwd}"
