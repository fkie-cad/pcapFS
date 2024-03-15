#!/bin/bash

git clone 'https://github.com/fkie-cad/pcapFS.git'
cd pcapFS
git checkout dev
./scripts/dependencies/install-all-dependencies.sh
mkdir build
cd build
cmake ..
make -j$(nproc)
#ln -s build/pcapfs /usr/bin
