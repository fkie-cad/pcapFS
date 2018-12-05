#!/bin/sh
set -eu

cd '/home/vagrant/pcapfs'
./scripts/dependencies/install-all-dependencies.sh
mkdir build
cd build
if [ "$(lsb_release -is)" = "CentOS" ]; then
    scl enable devtoolset-7 'cmake ..'
else
    cmake ..
fi
make
