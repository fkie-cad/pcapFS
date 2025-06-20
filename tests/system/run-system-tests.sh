#!/usr/bin/env bash
set -u

here="$(dirname $(readlink -e $0))"
venv="${here}/venv"

if [[ ! -d "${venv}" ]]; then
    echo '[NOTE] No virtualenv found. Creating one for you.' >&2
    python3 -m venv "${venv}"
fi

set +u
source "${venv}/bin/activate"
set -u

if [[ ! -f "${venv}/bin/pytest" ]]; then
    pip install -U -r "${here}/requirements.txt" > /dev/null
fi

if ! (type pcapfs > /dev/null 2>&1); then
    echo "[NOTE] pcapfs is not in your PATH. Adding default build directory (PROJECT_ROOT/build)." >&2
    PATH="${here}/../../build/:${PATH}"
fi

if ! (which fusermount3 > /dev/null 2>&1); then
    PATH="${here}/../../dependencies/bin/:${PATH}"
fi

set -e

if [[ $# -eq 0 ]]; then
    echo -e "\033[1;33mTesting pcap file...\033[0m"
    python3 -m pytest "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcap
    echo -e "\n\n\033[1;33mTesting pcapng file...\033[0m"
    python3 -m pytest "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcapng
elif [[ "$1" = "vagrant" ]]; then
    cd /home/vagrant/pcapfs/tests/system/
    python3 -m pytest "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcap
    python3 -m pytest "${here}/pcapfs-system-tests.py" -vv --testpcap system-tests.pcapng
fi
