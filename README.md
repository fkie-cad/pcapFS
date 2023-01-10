# pcapFS – Mounting Network Data
pcapFS is a FUSE module allowing it to mount captured network data as a virtual file system. This makes it especially 
convenient to analyze the payload (and to some extend the metadata) of your captured network traffic.

While there are already several tools out there which are able to extract data from your PCAPs, pcapFS has some 
features that make it different from these tools—most notably:

- fast and direct access to the payload (i.e. without prior extraction)
- support for multi/split PCAPs
- almost arbitrary sortable virtual directory hierarchy
- on the fly decoding and decrypting

Instead of extracting the payload (i.e. copying the data to disk), pcapFS provides direct access into the PCAP files. 
To speed the access up, an index is created when a PCAP is mounted for the first time. This takes almost the same time 
as opening a PCAP with Wireshark. After the index is created, we can use it for all further operations. Moreover, the 
index can be used to mount the PCAP any time later making the data available almost instantly.

# Protocols and Decoders
In pcapFS each protocol and decoder is implemented as a *virtual file*. These virtual files store references into other virtual files or directly into the PCAP, which are used to read their data. Currently the following protocols and decoders are supported:

- raw TCP and UDP
- HTTP 1.1
- FTP
- SSL (currently decryption is limited)
- DNS
- XOR

# Getting pcapFS
We do not provide any precompiled packages yet. This is mainly because a lot of the dependencies of pcapFS are also not 
available as packages in most of the Linux distribution around. So, for the moment you have to build pcapFS from source.

Building pcapFS works best on rather modern Linux distribution. See the [corresponding section](#building-pcapfs) of 
this README for further details.  

# Building pcapFS
As already mentioned, there are several dependencies which are not packaged for most Linux distributions. Moreover, you 
need a reasonably modern C++ compiler supporting at least C++14. Depending on your Linux distribution there are 
different steps required to compile pcapFS. Have a look at the scripts [here](scripts/dependencies).

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
will be in the current working directory and will be named somthing like `20181130-125450_pcapfs.index` (the first 
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
pcapFS lets you mount multiple PCAPs at the same time. The mount point will contain the payload of all PCAPs as if 
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
├── ssl
├── http
├── ftp
└── dns

6 directories, 0 files
```
That is, the first directory level contains the protocols detected and parsed by pcapFS. Within these directories you 
will find the payload of the corresponding conversations as files.

```
$ tree -r -L 2 /mnt/point/ | grep -A 3 -E ' (udp|tcp|ssl|http|dns)'
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
├── ssl
│   ├── 9997-656_SSL
│   ├── 999-5_SSL
│   ├── 9984-3081_SSL
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
| srcPort  | tcp, udp | Source port |
| domain   | http     | The domain parsed from the HTTP Host header |
| path     | http     | The path parsed from a HTTP request |

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
    ├── ssl
    │   └── PCAPFS_PROP_NOT_AVAIL
    │       └── 0-1838_SSL
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
directories for the protocols. There are additional `PCAPFS_PROP_NOT_AVAIL` folders in `tcp` and `ssl`. This is 
because the parsers for TCP and SSL do not provide the `domain` and `path` properties. The HTTP parser on the other 
hand provides these properties leading to the `server.test` and `image` subdirectories. 

## Decrypting and Decoding Traffic
It is possible for pcapFS to decrypt and decode certain protocols on the fly if you provide it with the corresponding 
key material. Right now, we have prototypical support for SSL/TLS and 
XOR. Both need a key file containing the key material which can be provided either via the command line (`-k` or 
`--keys`) or via the [configuration file](#configuration-file). The argument can be a single file or a directory 
containing multiple key files. Example key files can be found in the [tests folder](tests/system/keyfiles). Note that 
we are still in the process of deciding on an adequate file format, so be prepared for changes here.\
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

[[decode.xor.properties]]
  srcPort = 1111
  dstPort = 2222
  protocol = "udp"

[[decode.ssl.properties]]
  srcIP = "1.2.3.4"
  srcPort = 8080

```
The `[general]` section allows setting the `sortby` option described above.

The `[keys]` section allows you to define a list of paths to key files. Note that relative paths are interpreted as 
relative to the config file. Just as with the `-k` command line option, you are free to use files or directories here. 

The `[decode]` section can be used to provide custom protocol parsing and decoding rules. That is, you can tell pcapFS 
which parser to use for connections meeting given criteria. The example config above defines three rules, two for XOR 
decoding and one for SSL. As the `properties` key implies, you can use pcapFS properties to define your decoding rules. 
In case of the SSL example above, all connections from source IP 1.2.3.4 and source Port 8080 would be parsed with the 
SSL protocol parser. For XOR we defined two rules both stating that connection meeting the criteria should be parsed 
with the XOR parser: the first one matches all connections from source IP 1.2.3.4 to destination IP 4.3.2.1 and 
destination port 2345, the second one matches all UDP "connections" from source port 1111 to destination port 2222. 
Note that decoding options are independent from an implemented protocol detection. E.g. you can specify a certain port for HTTP decoding, but the HTTP parser still checks if the transferred data over this port is valid HTTP.

