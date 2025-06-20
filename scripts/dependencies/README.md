# Dependency Helper Scripts
This directory contains scripts to install all dependencies required to build pcapFS. These scripts are primarily used in our [build tests](../../tests/build), but you can also use them yourself.

If you are using one of the operating systems listed below, simply run [install-all-dependencies.sh](install-all-dependencies.sh) to install all necessary dependencies:

| Distribution    | Supported Releases       |
|-----------------|--------------------------|
| Fedora          | 37 and newer             |
| Ubuntu          | 20.04 and newer          |
| Debian          | 11, 12                   |
| Kali            | Rolling                  |
| Linux Mint      | 21 and newer             |
| CentOS Stream   | 9, 10                    |

## Disclaimer
Use these scripts at your own risk. We recommend to first look at what they do and check if they are okay for you and your system.

Most dependencies are either common packages (such as OpenSSL) installed from your distribution’s package repository, or are installed locally to the `3rdparty` (downloads) and `dependencies` (install prefix) directories in the root of your cloned repository.
