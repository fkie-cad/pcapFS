
LOCAL_REPO_PATH="${HERE}/../../3rdparty"
PREFIX="${HERE}/../../dependencies"

mkdir -p "${LOCAL_REPO_PATH}"
mkdir -p "${PREFIX}"

function clone_or_update_git_repo() {
    url="$1"
    pkgdir="$2"
    commit=''

    if [ $# -gt 2 ]; then
        commit="$3"
    fi
    if [ ! -d "${pkgdir}" ]; then
        git clone ${url} "${pkgdir}" --quiet
    else
        cd "${pkgdir}" || return
        default_branch="$(git branch -a | sed -nE 's;.*origin/HEAD.*origin/(.*);\1;p')"
        git checkout "${default_branch}"
        git pull --quiet
        cd ..
    fi
    if [ -n "${commit}" ]; then
        cd "${pkgdir}" && git checkout "${commit}" && cd ..
    fi
}
