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
    python3 -m pytest "${here}/pcapfs-crypto-tests-all-ciphers.py" -vv
    python3 -m pytest "${here}/pcapfs-crypto-tests-features.py" -vv
elif [[ "$1" = "vagrant" ]]; then
    cd /home/vagrant/pcapfs/tests/system/
    python3 -m pytest "${here}/pcapfs-crypto-tests-all-ciphers.py" -vv
    python3 -m pytest "${here}/pcapfs-crypto-tests-features.py" -vv
fi
