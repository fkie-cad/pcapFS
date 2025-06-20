# Changelog

## [Unreleased]
### Fixed
- Mismatched Allocation warning for newer GCC versions

### Added
- SMB2: option `--snapshot`
- SMB2, FTP: option `--timestamp-mode`
- FTP: more considered commands for server directory reconstruction
- Option `--snip`
- Automatic dependency installation for more Linux distributions

### Changed
- SMB2: Improvement of parsing order and internal management of file versions and timestamps


## [0.6.0]
### Fixed
- Support spaces in file names
- several bugfixes

### Added
- Add SMB2 as supported protocol
- Server-side directory hierarchy reconstruction for FTP and SMB2, including different file versions
- Add JA4, JA4S, JA4X and JA4H as properties
- Add option `--check-non-default-ports`
- FTP: support `Entering Extended Passive Mode`, handle `MLSD` files
- Cobalt Strike: support multiple possible AES keys per connection

### Changed
- Update dependencies, change to OpenSSL version 3
- Capture file type detection
- Improve UDP stream handling

## [0.5.0]
### Added
- Add support for PCAPNG files
- Support TLS decryption with key material which is embedded in PCAPNG files
- Add SSH and DHCP as supported protocol
- Add JA3, JA3S, hassh and hasshServer as properties for structuring the virtual directory hierarchy

## [0.4.0]
### Fixed
- Fix crash at FTP handling when PASS credentials are parsed, but not the corresponding USER credentials
- Add missing exception handling

### Added
- Decryption and parsing of Cobalt Strike C2 traffic when default profile is used and the team server's private RSA key is given, extraction and defragmentation of transferred files
- Add --no-cs flag to deactivate Cobalt Strike parsing
- Add support for multiple XOR key files
- SSL/TLS:
    - More cipher suites supported for TLS decryption
    - Decryption when private RSA key of Server or RSA PreMaster secret is passed
    - Support extended master secret and truncated HMAC extension, MAC-then-encrypt and encrypt-then-MAC
    - Extraction of TLS certificates as metadata file
    - Add SNI as domain property for TLS

### Changed
- Warning when config file is invalid
- When decode properties are defined in config, pcapFS only tries to decrypt the connections which satisfy the properties
- Update PcapPlusPlus dependency because of bugfix
- Buffering of once parsed and decoded content

## [0.3.1]
### Fixed
- Pin libfuse to release 3.4.2 until Fusepp catches up with master branch of libfuse (https://github.com/fkie-cad/pcapFS/issues/13)

## [0.3.0]
### Added
- Add preference values for DNS MX records
- Set the st_blocks attributes of the virtual files (https://github.com/fkie-cad/pcapFS/issues/10)

### Changed
- Allow multiple key files (-k/--keys) on the command line

## [0.2.1] - 2019-02-25
### Fixed
- Fix crash when the link layer protocol is not Ethernet (Issue #9)

## [0.2.0] - 2018-12-13
### Added
- Check that PCAP file names given on the command line match the ones stored in an index file

### Changed
- Make mount point optional when the --no-mount option is given on the command line
- Overwrite empty index files
- Require commit ae1b3c49a8cc448c5333b52abedc3467244d42a7 of PcapPlusPlus

## [0.1.0] - 2018-12-05
### Added
- Initial public release
