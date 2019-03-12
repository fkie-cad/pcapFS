# Changelog

## [0.3.0]
### Added
- Add preference values for DNS MX records
- Set the st_blocks attributes of the virtual files (Issue #10)

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
