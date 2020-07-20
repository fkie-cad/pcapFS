#!/bin/sh
set -eu

cd '/home/vagrant/pcapfs'
mkdir build
cd build
if [ "$(lsb_release -is)" = "CentOS" ]; then
    scl enable devtoolset-7 'cmake ..'
else
    cmake -DBUILD_TESTING=on ..
fi
make -j2
