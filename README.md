# pcapFS – Mounting Network Data
pcapFS is a FUSE module allowing it to mount captured network data as a virtual file system. This makes it especially
convenient to analyze the payload (and to some extend the metadata) of your captured network traffic.

While there are already several tools out there which are able to extract data from your PCAPs, pcapFS has some
features that make it different from these tools—most notably:

- fast and direct access to the payload (i.e. without prior extraction)
- support for multi/split PCAP and PCAPNG files
- almost arbitrary sortable virtual directory hierarchy
- on the fly decoding and decrypting
- direct extraction of files transferred over the network
- reconstruction of server-side file systems for protocols like SMB2 and FTP including different file versions (see [below](#reconstruction-of-the-server-side-directory-hierarchy-for-ftp-and-smb2))

Instead of extracting the payload (i.e. copying the data to disk), pcapFS provides direct access into the PCAP/PCAPNG files.
To speed the access up, an index is created when a PCAP is mounted for the first time. This takes almost the same time
as opening a PCAP with Wireshark. After the index is created, we can use it for all further operations. Moreover, the
index can be used to mount the PCAP any time later making the data available almost instantly.

# Protocols and Decoders
In pcapFS each protocol and decoder is implemented as a *virtual file*. These virtual files store references into other virtual files or directly into the PCAP/PCAPNG file, which are used to read their data. Currently the following protocols and decoders are supported:

- raw TCP and UDP
- HTTP 1.1
- TLS 1.0-1.2 (see [below](#decrypting-and-decoding-traffic))
- FTP
- SMB2
- SSH
- DNS
- DHCP
- XOR
- Cobalt Strike C2 (default profile, see [below](#decrypting-cobalt-strike-c2-traffic))

# Getting pcapFS
We do not provide any precompiled packages yet. This is mainly because some dependencies of pcapFS are also not
available as packages in most of the Linux distribution around. So, for the moment you have to build pcapFS from source.

Building pcapFS works best on a rather modern Linux distribution. See the [section below](#building-pcapfs) for further details.

# Building pcapFS
As already mentioned, there are some dependencies which are not packaged for most Linux distributions. Moreover, you
need a reasonably modern C++ compiler supporting at least C++14. Depending on your Linux distribution there are
different steps required to get all dependencies of pcapFS. Have a look at the scripts [here](scripts/dependencies).

Afterwards you can build pcapFS like:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

# Using pcapFS

## Mounting Network Data
The general way to mount a network capture looks like this:
```
$ pcapfs [options] <pcap> <mountpoint>
```

So, just mounting a single PCAP is as simple as:
```
$ pcapfs /path/to/some/test.pcap /mount/point
```

To unmount a previously mounted network capture use `fusermount3` with the `-u` switch:
```bash
$ fusermount3 -u /mount/point
```

Since the example above did not specify any index file, pcapFS automatically creates an index file for you. This file
will be in the current working directory and will be named something like `20181130-125450_pcapfs.index` (the first
component is the date when the index was created, the second the time, and the last one is just a fixed string). You can
use this index if you want to mount the PCAP again using the `-i` or `--index` switches:
```
$ pcapfs -i 20181130-125450_pcapfs.index /path/to/some/pcap /mount/point
```
If you provide a path to a non-existing index file on the command line, an index with this name will be created for
you.

If you don't want your index to be written to disk, use the `-m` or `--in-memory` options. This skips the writing of
the index which, of course, means that the index has to be rebuilt the next time you want to mount the PCAP.

## Mounting Multiple/Split PCAPs
pcapFS lets you mount multiple PCAP/PCAPNG files at the same time. The mount point will contain the payload of all PCAPs as if
only one PCAP would have been mounted. It makes no difference if the PCAPs you mount are completely unrelated or if
you are providing a very long network capture split into several PCAPs. Note that conversations spanning over two or
more PCAPs are entirely supported by pcapFS, i.e. no prior merging of PCAPs is required in order to extract your long
lasting download from multiple PCAPs!

For this purpose, you can specify a directory instead of a regular PCAP file:
```
$ pcapfs /path/to/some/pcaps/ /mount/point
```
In the example above pcapFS would try to mount all regular files contained in the `/path/to/some/pcaps` folder. If you
want to limit the files to be mounted, you can provide a file name suffix to only include files ending with this
suffix, e.g.
```
$ pcapfs --pcap-suffix=.pcap /path/to/some/pcaps/ /mount/point
```
This would tell pcapFS to only mount files ending with `.pcap` from the directory `/path/to/some/pcaps`.

## Sorting the Virtual Directory Hierarchy
If nothing else is specified, pcapFS will create a directory structure looking something like this:
```
$ pcapfs /path/to/some/test.pcap /mnt/point
$ tree -r -L 1 /mnt/point
/mnt/point/
├── udp
├── tcp
├── tls
├── http
├── ftp
└── dns

6 directories, 0 files
```
That is, the first directory level contains the protocols detected and parsed by pcapFS. Within these directories you
will find the payload of the corresponding conversations as files.

```
$ tree -r -L 2 /mnt/point/ | grep -A 3 -E ' (udp|tcp|tls|http|dns)'
├── udp
│   ├── 0-9_UDPFILE3
│   ├── 0-99816_UDPFILE1522
│   ├── 0-99773_UDPFILE1521
--
├── tcp
│   ├── 0-99886_tcp3927
│   ├── 0-9977_tcp687
│   ├── 0-99112_tcp3922
--
├── tls
│   ├── 9997-656_TLS
│   ├── 999-5_TLS
│   ├── 9984-3081_TLS
--
├── http
│   ├── 998-811
│   ├── 9986-93333_icons-16x16.png
│   ├── 9986-81178_header-desk-logo.png
--
└── dns
    ├── 998-0_RES-18314
    ├── 997-0_REQ-18314
    ├── 99-0_RES-63051

```
pcapFS is, however, not limited to this directory layout. Instead, it lets you choose the layout that is most suitable
for your current analysis. For instance, assume that you are interested in the ports a particular host has send packets
to. In this case you could call pcapFS like this:
```
$ pcapfs --sortby=/srcIP/dstPort/dstIP /path/to/some/test.pcap /mount/point
```
After that your directory hierarchy should look like the following:
```
$ tree -rd -L 3 /mnt/point/
/mnt/point/
...
├── 172.16.139.241
│   └── 53
│       └── 172.16.128.202
├── 172.16.133.99
│   ├── 8200
│   │   └── 67.217.88.86
│   ├── 5500
│   │   └── 172.16.139.250
│   ├── 443
│   │   ├── 96.43.146.48
│   │   ├── 96.43.146.22
│   │   ├── 96.43.146.176
│   │   ├── 64.74.80.70
│   │   ├── 64.74.80.15
│   │   ├── 216.219.115.54
│   │   ├── 216.219.115.17
│   │   ├── 216.115.217.144
│   │   ├── 216.115.216.44
│   │   ├── 216.115.209.97
│   │   ├── 216.115.208.199
│   │   ├── 173.194.43.3
│   │   └── 157.56.240.102
│   ├── 1900
│   │   └── 239.255.255.250
│   ├── 1853
│   │   └── 67.217.78.32
│   ├── 138
│   │   └── 172.16.133.255
│   └── 137
│       └── 172.16.133.255
├── 172.16.133.97
│   ├── 8014
│   │   └── 172.16.128.169
│   ├── 5500
│   │   └── 172.16.139.250
│   ├── 5462
│   │   └── 172.16.139.250
│   ├── 5447
│   │   └── 172.16.139.250
│   ├── 443
│   │   ├── 96.43.146.22
│   │   ├── 96.43.146.176
│   │   └── 157.56.240.102
│   ├── 1900
...
```
The `--sortby` argument used above defines the layout of the virtual directory hierarchy created for you. pcapFS
provides what we call *properties* for this. The following table lists the properties which are currently available
along with the protocol they origin from:

| Property | Protocol | Description |
| -------- | -------- | ----------- |
| protocol | *n/a*    | A protocol implemented in pcapFS |
| srcIP    | ip       | Source IP address |
| dstIP    | ip       | Destination IP address |
| srcPort  | tcp, udp | Source port |
| dstPort  | tcp, udp | Destination port |
| domain   | http, tls     | The domain parsed from the HTTP Host header and SNI|
| uri     | http     | The requested URI parsed from the HTTP request|
| ja3     | tls (http) | MD5 hash of JA3 fingerprint |
| ja3s    | tls (http) | MD5 hash of JA3S fingerprint |
| ja4     | tls (http) | JA4 fingerprint |
| ja4s    | tls (http) | JA4S fingerprint |
| ja4x    | tls (http) | JA4X fingerprint |
| ja4h    | http | JA4H fingerprint |
| hassh   | ssh      | hassh fingerprint of SSH connection |
| hasshServer | ssh   | hasshServer fingerprint of SSH connection |

A protocol implemented in pcapFS can define its own properties based on values it parsed. Therefore, as more and more
protocols are added to pcapFS, you will have very fine grained possibilities to build your directory hierarchy.

Note that the current implementation does not check whether a property you specified actually exists. That is, you
could also provide the following `sortby` argument:
```
$ pcapfs --sortby=/foo/protocol/domain/path /path/to/some/test.pcap /mount/point
/mount/point
└── PCAPFS_PROP_NOT_AVAIL
    ├── tcp
    │   └── PCAPFS_PROP_NOT_AVAIL
    │       ├── 0-139_tcp10
    │       └── 0-131_tcp9
    ├── tls
    │   └── PCAPFS_PROP_NOT_AVAIL
    │       └── 0-1838_TLS
    └── http
        └── server.test
            ├── image
            │   ├── 8-308_png
            │   └── 7-311_jpeg
            ├── 6-309_json
            ├── 5-333_gzip
            ├── 4-339_deflate
            ├── 3-318_html
            ├── 2-312_headers
            └── 1-306_ip

8 directories, 11 files
```
As you can see, the `foo` component lead to the creation of the `PCAPFS_PROP_NOT_AVAIL` folder containing the
directories for the protocols. There are additional `PCAPFS_PROP_NOT_AVAIL` folders in `tcp` and `tls`. This is
because the parsers for TCP and TLS do not provide the `domain` and `path` properties. The HTTP parser on the other
hand provides these properties leading to the `server.test` and `image` subdirectories.

## Showing Metadata Files with `--show-metadata`
When you pass the option `--show-metadata` to pcapFS, additional files with useful metadata information are created. Depending on the protocol, different information is extracted for metadata files:
- TLS: all certificates of the server-side certificate chain
- HTTP: headers from requests and responses
- SMB2: control files containing transferred commands and responses per connection as well as empty files from the reconstructed server-side directory hierarchy
- FTP: control files and credential files containing the client's login credentials

## Decrypting and Decoding Traffic
It is possible for pcapFS to decrypt and decode certain protocols on the fly if you provide it with the corresponding
key material. Right now, we have prototypical support for TLS, Cobalt Strike and XOR. For decryption, these protocols need a key file containing the key material which can be provided via the command line (`-k` or
`--keys`) or via the [configuration file](#configuration-file). For TLS key files, pcapFS also supports decryption when the key material is already embedded in the corresponding PCAPNG file (for further reference see [here](https://wiki.wireshark.org/TLS#embedding-decryption-secrets-in-a-pcapng-file)). When providing the key material via the command line, the argument can be a single file or a directory containing multiple key files.
For TLS decrpytion, supported key file formats are the same as for Wireshark:
- key log files in NSS Key Log Format generated by applications when the environment variable `SSLKEYLOGFILE` is set. We support the format `CLIENT_RANDOM <ClientRandom> <MasterSecret>` and `RSA <first 8 bytes of encrypted preMasterSecret> <preMasterSecret>` for RSA key exchange.
- RSA private key file of server. Then, we decrypt all TLS traffic that uses RSA key exchange and whose server certificate matches the private key.

Example key files can be found in the [tests folder](tests/system/keyfiles).
Currently supported cipher suites are:
| ID | Cipher Suite | ID | Cipher Suite |
|----|--------------|----|--------------|
| 0x0004 | `TLS_RSA_WITH_RC4_128_MD5` | 0x009D | `TLS_RSA_WITH_AES_256_GCM_SHA384` |
| 0x0005 | `TLS_RSA_WITH_RC4_128_SHA` | 0x009E | `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` |
| 0x0018 | `TLS_DH_anon_WITH_RC4_128_MD5` | 0x009F | `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` |
| 0x002F | `TLS_RSA_WITH_AES_128_CBC_SHA` | 0x00A6 | `TLS_DH_anon_WITH_AES_128_GCM_SHA256` |
| 0x0033 | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | 0x00A7 | `TLS_DH_anon_WITH_AES_256_GCM_SHA384` |
| 0x0034 | `TLS_DH_anon_WITH_AES_128_CBC_SHA` | 0xC011 | `TLS_ECDHE_RSA_WITH_RC4_128_SHA` |
| 0x0035 | `TLS_RSA_WITH_AES_256_CBC_SHA` | 0xC013 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` |
| 0x0039 | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` | 0xC014 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` |
| 0x003A | `TLS_DH_anon_WITH_AES_256_CBC_SHA` | 0xC016 | `TLS_ECDH_anon_WITH_RC4_128_SHA` |
| 0x003C | `TLS_RSA_WITH_AES_128_CBC_SHA256` | 0xC018 | `TLS_ECDH_anon_WITH_AES_128_CBC_SHA` |
| 0x003D | `TLS_RSA_WITH_AES_256_CBC_SHA256` | 0xC019 | `TLS_ECDH_anon_WITH_AES_256_CBC_SHA` |
| 0x0067 | `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256` | 0xC027 | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` |
| 0x006B | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256` | 0xC028 | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` |
| 0x006C | `TLS_DH_anon_WITH_AES_128_CBC_SHA256` | 0xC02F | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| 0x006D | `TLS_DH_anon_WITH_AES_256_CBC_SHA256` | 0xC030 | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
| 0x009C | `TLS_RSA_WITH_AES_128_GCM_SHA256` |

### Decrypting Cobalt Strike C2 Traffic
PcapFS supports prototypical decryption of Cobalt Strike C2 traffic as long as the Cobalt Strike default profile is used.
In order to successfully decrypt the C2 traffic, the team server's private RSA key is required which has to be passed in PEM format as a key file via the command line (`-k` or
`--keys`) or via the [configuration file](#configuration-file). The Cobalt Strike functionality of pcapFS includes decryption of server commands and the respective answers from beacons as well as extraction of transferred files.

The team server's private RSA key may be known when a cracked Cobalt Strike version is used. How the private key can be extracted in that case, is explained in a [blog post by Didier Stevens](https://blog.nviso.eu/2021/10/21/cobalt-strike-using-known-private-keys-to-decrypt-traffic-part-1/). You can exemplarily test the decryption and parsing capabilities of pcapFS with the pcap file referenced in [this post by Malware Traffic Analysis](https://www.malware-traffic-analysis.net/2021/02/02/index.html).

With the command line option `--no-cs` set, pcapFS does not try to decrypt Cobalt Strike traffic which may improve the overall performance.

## Reconstruction of the Server-Side Directory Hierarchy for FTP and SMB2
When analyzing a capture file that contains FTP or SMB2 traffic, pcapFS attempts to reconstruct the directory hierarchy of the corresponding FTP or SMB2 server including all files as far as possible. For this, pcapFS follows per connection the current working directory and parses all messages which indicate which files are located there.

For FTP traffic, the reconstructed directory hierarchy only includes downloaded files and empty files whose metadata is extracted via `MLSD` commands.

For SMB2 traffic, more information can be extracted, enabling a more detailed directory reconstruction. Files accessed directly via SMB2 Read/Write messages are populated with the corresponding file content that is read or written. Additionally, during the handling of SMB2 Read/Write messages, different file versions are created (indicated by the file name tag `@<file version number>`) each time the content changes. All other files, which are known to exist only from context, are created as empty files with the extracted metadata set. To also display these empty files, the `--show-metadata` option must be enabled. More infos on how pcapFS reconstructs SMB shares can be found in our paper [Mount SMB.pcap: Reconstructing file systems and file operations from network traffic](https://www.sciencedirect.com/science/article/pii/S2666281724001318) and in the [wiki page](https://github.com/fkie-cad/pcapFS/wiki/SMB-Documentation)

### Timestamp Modes for SMB2 files
Usually, the virtual files created by pcapFS are equipped with network timestamps, which were stored in the capture file for each packet. However, when reconstructing SMB shares, pcapFS uses the actual timestamps from the SMB shares themselves. These filesystem timestamps are communicated via the SMB2 packets in the capture file and differ from the network timestamps. But, since the communicated filesystem timestamps are not always reliable and cannot be determined in all scenarios, pcapFS follows a hybrid approach by default. This means pcapFS uses the communicated filesystem timestamps but updates them manually when a read/write operation is parsed. This approach also accounts for possible time skews between network and filesystem time that may occur when there is a time discrepancy between the recording device and the SMB share. If you prefer the SMB files to use network or unmodified filesystem timestamps, you can set the option `--timestamp-mode` and pass `network` or `fs` accordingly.

### Option `--snapshot` for SMB2 files
Apart from seeing all versions of reconstructed files from an SMB share captured over time, it is also possible to display the SMB share state at a specific point in time. To do this, use the `--snapshot` option and provide the desired point in time (unix timestamp or format `yyyy-MM-ddTHH:mm:ssZ` in UTC). By default, you need to specify the timestamp based on the filesystem timestamps from the SMB share, not the network timestamps from the capture file. If the option `--timestamp-mode` is set to `network`, then the SMB files are equipped with the network timestamps instead and the time specified via `--snapshot` will be treated as a network timestamp. Note that, when `--timestamp-mode=network` is set, the specified snapshot time must be within the time interval in which the SMB traffic was recorded.

## Option `--snip`
To consider only a specific portion of the provided capture file(s) and ignore all other recorded traffic, the `--snip` option can be used. With `--snip`, two comma-separated time strings (unix time stamps or time format `yyyy-MM-ddTHH:mm:ssZ` in UTC) need to be specified that define the time interval of the traffic to be included (`--snip <startTime>,<endTime>`). For example, to consider all traffic from timestamp 1730289978 onwards, use `--snip 1730289978,`.


## Configuration File
pcapFS uses [TOML](https://github.com/toml-lang/toml) as the format for its configuration file. A sample config file
looks like this:

```toml
[general]
  sortby = "/dstIP/dstPort/srcIP"

[keys]
  keyfiles = [
    "/path/to/some/key.file",
    "relative/path/to/other/key.file",
  ]


[[decode.xor.properties]]
  srcIP = "1.2.3.4"
  dstIP = "4.3.2.1"
  dstPort = 2345
  keyfile = "/path/to/some/xor1.key"

[[decode.xor.properties]]
  srcPort = 1111
  dstPort = 2222
  protocol = "udp"
  keyfile = "relative/path/to/some/xor2.key"

[[decode.tls.properties]]
  srcIP = "1.2.3.4"
  srcPort = 8080

[[decode.cobaltstrike.properties]]
  dstIP = "5.6.7.8"
  srcIP = "8.7.6.5"
  dstPort = 8080

```
The `[general]` section allows setting the `sortby` option described above.

The `[keys]` section allows you to define a list of paths to key files. Note that relative paths are interpreted as
relative to the config file. Just as with the `-k` command line option, you are free to use files or directories here.

The `[decode]` section can be used to provide custom protocol parsing and decoding rules. That is, you can tell pcapFS
which parser to use for connections meeting given criteria. The example config above defines four rules, two for XOR
decoding, one for TLS and one for Cobalt Strike. As the `properties` key implies, you can use pcapFS properties to define your decoding rules.
In case of the TLS example above, all connections from source IP 1.2.3.4 and source port 8080 would be parsed with the
TLS protocol parser. For XOR we defined two rules both stating that connection meeting the criteria should be parsed
with the XOR parser: all connections from source IP 1.2.3.4 to destination IP 4.3.2.1 and
destination port 2345 should be decrypted using the key file `xor1.key` and all UDP streams from source port 1111 to destination port 2222 should be decrypted using `xor2.key`. Notice that for XOR the `keyfile` property is mandatory in order to match the connection to be decoded.

Providing properties in the decode section can improve the runtime of pcapFS since only connections which meet the given criteria are decoded. If no decoding properties or no configuration file is provided, *all* TLS and Cobalt Strike traffic is tried to be decrypted using the keyfiles passed to pcapFS.

Note that decoding options are independent from an implemented protocol detection. E.g. you can specify a certain port for HTTP decoding, but the HTTP parser still checks if the transferred data over this port is valid HTTP.
