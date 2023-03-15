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

py.test "${here}/pcapfs-crypto-tests-all-ciphers.py" -vv
