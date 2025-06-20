#!/bin/sh
set -eu

# this script is executed during platform tests

cd '/home/vagrant/pcapfs'
./scripts/dependencies/install-all-dependencies.sh
./scripts/dependencies/install-catch2.sh
mkdir build
cd build
cmake -DBUILD_TESTING=on ..
make -j2
