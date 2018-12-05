#!/usr/bin/env bash
set -eu

saved_pwd="$(pwd -P)"

function determine_distro() {
    lsb_release="$(which lsb_release 2> /dev/null)"
    if [ -n "${lsb_release}" ]; then
        echo "$(lsb_release -is)"
        return
    fi
    if [ -f '/etc/centos-release' ]; then
        echo 'CentOS'
        return
    fi
}

function determine_release() {
    distro="$1"
    if [ "${distro}" = 'CentOS' ]; then
        sudo yum install -y redhat-lsb-core
    fi
    lsb_release="$(which lsb_release)"
    if [ -n "${lsb_release}" ]; then
        echo "$(${lsb_release} -rs)"
    else
        echo "Error: Please make sure that 'lsb_release' is available on your system!" >&2
        exit 2
    fi
}


distro="$(determine_distro)"
release="$(determine_release "${distro}")"

install_dependencies=''
if [ "${distro}" = 'Ubuntu' ]; then
    install_dependencies='install-ubuntu-dependencies.sh'
elif [ "${distro}" = 'CentOS' ]; then
    sudo yum install -y redhat-lsb-core
    install_dependencies='install-centos-dependencies.sh'
else
    echo 'Your distribution is not yet supported by this script.' >&2
    exit 1
fi

here=$(dirname $(readlink -e $0))
${here}/${install_dependencies}

cd "${saved_pwd}"
