#!/usr/bin/env bash
set -eu

saved_pwd="$(pwd -P)"

function determine_distro() {
    lsb_release="$(which lsb_release 2> /dev/null)"
    if [[ -n "${lsb_release}" ]]; then
        echo "$(lsb_release -is | tail -n 1)"
        return
    fi
    if [[ -f '/etc/centos-release' ]]; then
        echo 'CentOS'
        return
    fi
    if [[ -f '/etc/fedora-release' ]]; then
        echo 'Fedora'
        return
    fi
}

distro="$(determine_distro)"

install_dependencies=''
if [[ "${distro}" = 'Ubuntu' || "${distro}" = 'Kali' || "${distro}" = 'Linuxmint' ]]; then
    install_dependencies='install-ubuntu-dependencies.sh'
elif [[ "${distro}" = 'CentOS' ]]; then
    sudo yum install -y redhat-lsb-core
    install_dependencies='install-centos-dependencies.sh'
elif [[ "${distro}" = 'Fedora' ]]; then
    sudo dnf install -y lsb_release
    install_dependencies='install-fedora-dependencies.sh'
else
    echo 'Your distribution is not yet supported by this script.' >&2
    exit 1
fi

here=$(dirname $(readlink -e $0))
${here}/${install_dependencies}

cd "${saved_pwd}"
