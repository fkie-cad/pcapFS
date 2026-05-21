# Dependency Helper Scripts
This directory contains scripts to install all dependencies required to build pcapFS. They are invoked by [`bootstrap.sh`](../../bootstrap.sh) and by the [Platform Tests CI workflow](../../.github/workflows/build.yml), but you can also use them yourself.

If you are using one of the operating systems listed below, simply run [install-all-dependencies.sh](install-all-dependencies.sh) to install all necessary dependencies:

| Distribution    | Supported Releases             |
|-----------------|--------------------------------|
| Ubuntu          | 20.04, 22.04, 24.04, 26.04     |
| Debian          | 11, 12, 13                     |
| Kali            | Rolling                        |
| Linux Mint      | 21.x, 22.x                     |
| Fedora          | 40 and newer                   |
| CentOS Stream   | 9, 10                          |

## Disclaimer
Use these scripts at your own risk. We recommend to first look at what they do and check if they are okay for you and your system.

