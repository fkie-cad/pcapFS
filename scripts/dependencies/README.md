# Dependency Helper Scripts
The scripts provided in this directory will install the dependencies required to build pcapFS. We mainly use them in
our [build tests](../../tests/build). While you are free to use them on your own system, here's a word of
caution: especially on the older platforms we perform some actions that you would not want on a production system
(e.g. adding third party repositories, globally installing packages via pip etc.). We recommend not to use the scripts
without checking whether what they do is okay for you and your system!

The `install-some-package.sh` scripts are less risky to use---they download and install the corresponding packages
to `3rdparty` (downloads) and `dependencies` (install prefix) in the root directory of your cloned repository.

If you have Ubuntu, Kali or Fedora, you can just run [install-all-dependencies.sh](install-all-dependencies.sh) and all necessary dependencies are installed automatically.

## Disclaimer
Use these scripts at your own risk!
