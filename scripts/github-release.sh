#!/bin/bash
set -eu

here=$(dirname $(readlink -e $0))

old_version="$(git describe --tag --abbrev=0)"
old_version="${old_version:1}"  # strip leading "v"
new_version="$(sed -nE 's/project\(.*VERSION\s([0-9]+\.[0-9]+\.[0-9]+)\s.*\)$/\1/p' ${here}/../CMakeLists.txt)"
current_branch="$(git symbolic-ref --short HEAD)"


function yesno() {
    read yn
    case "${yn}" in
        y|Y) echo 'y' ;;
        *) echo 'n' ;;
    esac
}

if [[ "${current_branch}" != 'dev' ]]; then
    echo '[!] Error: You have to be in the dev branch to make a new release.'
    exit 1
fi

if [[ "${old_version}" = "${new_version}" ]]; then
    echo -n "[!] Error: version string in CMakeLists.txt is still set to the latest tagged version "
    echo "(\"${new_version}\" == \"${old_version}\")."
    exit 2
fi

if ! git diff --quiet; then
    git --no-pager diff --stat
    echo '[!] "dev" branch is dirty. Please review the changes listed above.'
    echo -n '[?] Do you want to continue? [y/N] '
    yn="$(yesno)"
    if [[ "${yn}" != 'y' ]]; then
        echo '[!] Exiting.'
        exit 0
    fi
fi

echo -n '[?] Did you update the change log? [y/N] '
yn="$(yesno)"
if [[ "${yn}" = 'y' ]]; then
    echo '[*] Updating version in CHANGELOG.md'
    sed -i "s/\[Unreleased\]/[${new_version}]/" "${here}/../CHANGELOG.md"
    git commit -S "${here}/../CHANGELOG.md" -m 'Update version'
else
    echo '[!] Exiting.'
    exit 2
fi

echo '[!] Commits in "dev but not in "main":'
git --no-pager log --left-right --graph --cherry-pick --oneline main..dev
echo -n '[?] Do you want to merge these commit into the "main" branch? [y/N] '
yn="$(yesno)"
if [[ "${yn}" = 'y' ]]; then
    echo '[*] Merging "dev" into "main"'
    git checkout main
    git merge dev
else
    echo '[!] Exiting.'
    echo 2
fi

git tag -s -a "v${new_version}" -m "Tag version ${new_version}"
git push
git push --tags

git checkout dev
sed -i -E "0,/\[${new_version}\]/s/\[${new_version}\]/[Unreleased]\n\n## &/" "${here}/../CHANGELOG.md"
git commit "${here}/../CHANGELOG.md" -m 'Add Unreleased section'
git push

echo '[*] Done. Please remember to delete obsolete branches.'
