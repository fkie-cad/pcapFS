#!/bin/sh
set -eu

cd '/home/vagrant/pcapfs'
./scripts/dependencies/install-all-dependencies.sh
./scripts/dependencies/install-catch2.sh
