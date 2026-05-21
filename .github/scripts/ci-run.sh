#!/usr/bin/env bash
# Bootstraps a minimal Docker container for CI platform testing.
# Installs distro-specific prerequisites, builds pcapFS, and runs all test suites.
set -euo pipefail

. /etc/os-release

case "$ID" in
    ubuntu|debian|kali|linuxmint)
        apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y sudo lsb-release wget
        ;;
    fedora|centos)
        dnf install -y sudo git which findutils wget
        ;;
    *)
        echo "Unsupported distribution: $ID" >&2
        exit 1
        ;;
esac

# Minimal container images (notably Fedora's) ship a sudo whose PAM stack
# cannot resolve users — even root invocations fail. Since we're already root
# in CI, install a passthrough wrapper that just execs the command.
cat > /usr/local/bin/sudo <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        *=*) export "$1"; shift ;;
        *) break ;;
    esac
done
exec "$@"
EOF
chmod +x /usr/local/bin/sudo
hash -r

./scripts/dependencies/install-all-dependencies.sh
./scripts/dependencies/install-catch2.sh

# CMAKE_POLICY_VERSION_MINIMUM lets transitive FetchContent dependencies that
# still use cmake_minimum_required(< 3.5) configure under CMake 4.x (Ubuntu 26.04).
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=on -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build -j"$(nproc)"

./build/unittests
./tests/system/run-system-tests.sh
./tests/crypto/run-crypto-tests.sh
