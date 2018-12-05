
LOCAL_REPO_PATH="${HERE}/../../3rdparty"
PREFIX="${HERE}/../../dependencies"

mkdir -p "${LOCAL_REPO_PATH}"
mkdir -p "${PREFIX}"

function clone_or_update_git_repo() {
    url="$1"
    pkgdir="$2"
    if [ ! -d "${pkgdir}" ]; then
        git clone ${url} "${pkgdir}" --quiet
    else
        cd "${pkgdir}" && git pull --quiet && cd ..
    fi
}