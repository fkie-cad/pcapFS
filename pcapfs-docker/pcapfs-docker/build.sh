#!/bin/bash
echo "Installation File:"
git clone https://github.com/fkie-cad/pcapFS.git
git checkout experimental
cd pcapFS
ls -lah
./scripts/dependencies/install-all-dependencies.sh   #optional, if you don't want to install everything yourself (use at your own risk)
./scripts/dependencies/install-catch2.sh             #optional, if you don't want to install everything yourself (use at your own risk)
mkdir build
cd build
cmake -DBUILD_TESTING=on ..
make -j$(nproc)
