#!/usr/bin/env bash
set -u

here="$(dirname $(readlink -e $0))"
venv="${here}/venv"
virtualenv="$(which virtualenv)"
python='python3.8'

if ! (type pcapfs > /dev/null 2>&1); then
    echo "[NOTE] pcapfs is not in your PATH. Adding default build directory (PROJECT_ROOT/build)." >&2
    PATH="${here}/../../build/:${PATH}"
fi

if ! (which fusermount3 > /dev/null 2>&1); then
    PATH="${here}/../../dependencies/bin/:${PATH}"
fi

set -e

if [[ -z "${virtualenv}" ]]; then
    echo 'virtualenv is required to run this script.' >&2
    exit 1
fi

if [[ ! -d "${venv}" ]]; then
    echo '[NOTE] No virtualenv found. Creating one for you.' >&2
    ${virtualenv} -p"${python}" "${venv}" > /dev/null
    set +u
    source "${venv}/bin/activate"
    set -u
    pip install -U -r "${here}/requirements.txt" > /dev/null
fi

set +u
source "${venv}/bin/activate"
set -u

if [[ $# -eq 0 ]]; then
    echo -e "\033[1;33mTesting pcap file...\033[0m"
    py.test "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcap
    echo -e "\n\n\033[1;33mTesting pcapng file...\033[0m"
    py.test "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcapng
elif [[ "$1" = "vagrant" ]]; then
    cd /home/vagrant/pcapfs/tests/system/
    py.test "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcap
    py.test "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcapng
fi
