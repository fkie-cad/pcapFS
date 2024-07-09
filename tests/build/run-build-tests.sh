#!/usr/bin/env bash
set -Eeu

declare -A PLATFORMS=(
    ['fedora-37']="Fedora 37"
    ['fedora-38']="Fedora 38"
    ['fedora-39']="Fedora 39"
    ['fedora-40']="Fedora 40"
    ['ubuntu-18.04']="Ubuntu 18.04"
    ['ubuntu-20.04']="Ubuntu 20.04"
    ['ubuntu-22.04']="Ubuntu 22.04"
    ['ubuntu-24.04']="Ubuntu 24.04"
    ['kali']="Kali"
    ['centos-7']="CentOS 7"
)


function print_usage() {
    echo 'Usage: run-build-tests.sh [OPTIONS] PLATFORM [PLATFORM] [...]'
    echo
    echo 'Valid OPTIONS are:'
    echo '  -h, --help      Display this help and exit'
    echo
    echo 'Valid PLATFORMs are:'
    echo -e "  all\t\t    alias for all platforms listed below"
    for p in "${!PLATFORMS[@]}"; do
        echo -e "  ${p}\t    ${PLATFORMS[${p}]}"
    done | sort
    echo
    echo 'You can also provide "all" instead of a specific platform to run the'
    echo 'build tests for all supported platforms listed above.'
}


RUN_FOR_ALL='no'
TEST_COUNT=0
ERR_COUNT=0

PARAMS=()
while (( "$#" )); do
    case "$1" in
        -h|--help)
            print_usage; exit 0 ;;
        -*|--*=)
            echo "Error: Unknown argument '$1'" >&2
            echo
            print_usage
            exit 1
            ;;
        *)
            if [ "$1" = "all" ]; then
                RUN_FOR_ALL='yes'
            fi
            PARAMS+=("$1")
            shift ;;
    esac
done
set -- "${PARAMS[@]}"


function run_build_test() {
    platform="$1"
    log="build-tests-${platform}.log"
    TEST_COUNT=$((TEST_COUNT+1))
    result='fail'
    echo "[$(date +'%F %T') | ${platform} | start]" | tee -a "${log}"
    set +e
    vagrant up "${platform}" >> "${log}" 2>&1
    vagrant ssh "${platform}" -c "/home/vagrant/pcapfs/tests/build/build-pcapfs.sh" >> "${log}" 2>&1
    err=$?
    if [ ${err} -eq 0 ]; then
        result='success'
    fi
    set -e
    vagrant destroy -f "${platform}" >> "${log}" 2>&1
    echo "[$(date +'%F %T') | ${platform} | ${result}]" | tee -a "${log}"
    if [ "${result}" = 'success' ]; then
        rm -f "${log}"
    fi
}


function err_trap() {
    ERR_COUNT=$((ERR_COUNT+1))
}


trap err_trap ERR

if [ $# -eq 0 ]; then
    echo 'Error: Not enough arguments! You have to specify at least one platform.'
    echo
    print_usage
    exit 1
fi


if [ "${RUN_FOR_ALL}" = 'yes' ]; then
    for p in "${!PLATFORMS[@]}"; do
        run_build_test "${p}"
    done
else
    set +u
    for p in "${PARAMS[@]}"; do
        if [ -n "${PLATFORMS[$p]}" ]; then
            run_build_test "${p}"
        else
            echo "Skipping unknown architecture ${p}"
        fi
    done
fi

echo "[$(date +'%F %T') | summary | tests: ${TEST_COUNT} | successful: $((TEST_COUNT-ERR_COUNT)) | failed: ${ERR_COUNT}]"
exit ${ERR_COUNT}
