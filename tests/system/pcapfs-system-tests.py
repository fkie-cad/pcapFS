#!/usr/bin/env python3
import os
import random
import string
import subprocess
import tempfile
import binascii
from contextlib import contextmanager
from pathlib import Path

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))


class TestBasicFunctionality:
    def test_pcap_gets_mounted(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert os.path.ismount(mountpoint)

    def test_mount_point_is_not_empty(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert len(os.listdir(mountpoint)) > 0

    def test_mount_point_contains_all_directories(self, testpcap):
        with mount_pcap(testpcap) as mountpoint:
            assert os.listdir(mountpoint) == [
                "dhcp",
                "dns",
                "http",
                "ssh",
                "ssl",
                "tcp",
            ]

    def test_mount_point_contains_all_files(self, testpcap, expected_files):
        with mount_pcap(testpcap) as mountpoint:
            files = list()
            for d in ["dhcp", "dns", "http", "ssh", "ssl", "tcp"]:
                files.extend(
                    os.path.join(d, f) for f in os.listdir(os.path.join(mountpoint, d))
                )
        assert sorted(files) == expected_files


class TestSortByOption:
    def test_dst_port(self, testpcap):
        expected_files = (
            "67/0-0_REQ-15645",
            "68/1-0_RES-15645",
            "53/2-0_REQ-28663",
            "32795/2-28_RES-28663",
            "52240/8-308_png",
            "52236/7-311_jpeg",
            "52230/6-309_json",
            "52228/5-333_gzip",
            "52226/4-339_deflate",
            "52222/3-318_html",
            "52220/2-312_headers",
            "52218/1-306_ip",
            "60906/11-2338_SSH-5",
            "22/11-2526_SSH-6",
            "443/0-1838_SSL",
            "12345/0-135_tcp9",
            "54321/0-143_tcp10",
        )
        with mount_pcap(testpcap, params=["--sortby=dstPort"]) as mountpoint:
            assert get_file_list(mountpoint) == sorted(expected_files)

    def test_ja3_ja3s(self, testpcap):
        expected_files = (
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-0_REQ-15645",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/1-0_RES-15645",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-0_REQ-28663",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-28_RES-28663",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/8-308_png",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/7-311_jpeg",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/6-309_json",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/5-333_gzip",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/4-339_deflate",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/3-318_html",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-312_headers",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/1-306_ip",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/11-2338_SSH-5",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/11-2526_SSH-6",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-135_tcp9",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-143_tcp10",
            "1949310ab64717817ba98300d889efb3/48ed6c8d9eb6d18b50b12cee7c730ef5/0-1838_SSL",
        )
        with mount_pcap(testpcap, params=["--sortby=ja3/ja3s"]) as mountpoint:
            assert get_file_list(mountpoint) == sorted(expected_files)

    def test_hassh_hasshserver(self, testpcap):
        expected_files = (
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-0_REQ-15645",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/1-0_RES-15645",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-0_REQ-28663",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-28_RES-28663",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/8-308_png",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/7-311_jpeg",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/6-309_json",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/5-333_gzip",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/4-339_deflate",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/3-318_html",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/2-312_headers",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/1-306_ip",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-135_tcp9",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-143_tcp10",
            "PCAPFS_PROP_NOT_AVAIL/PCAPFS_PROP_NOT_AVAIL/0-1838_SSL",
            "0df0d56bb50c6b2426d8d40234bf1826/a95c22bf8e9b19ed0a5dc74bb2f9c613/11-2338_SSH-5",
            "0df0d56bb50c6b2426d8d40234bf1826/a95c22bf8e9b19ed0a5dc74bb2f9c613/11-2526_SSH-6",
        )
        with mount_pcap(testpcap, params=["--sortby=hassh/hasshServer"]) as mountpoint:
            assert get_file_list(mountpoint) == sorted(expected_files)


class TestSsl:
    def test_with_single_ssl_key_file(self, testpcap, expected_files_with_ssl):
        with mount_pcap(
            testpcap, params=["-k", "{here}/keyfiles/ssl.key".format(here=HERE)]
        ) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


class TestSslFileReadRaw:
    def test_read_raw_ssl_rc4_full_appdata(
        self, testpcap, content_tls_appdata_all_cipher
    ):
        with mount_pcap(testpcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "ssl/0-1838_SSL" in files
            with open(os.path.join(mountpoint, "ssl/0-1838_SSL"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_tls_appdata_all_cipher


class TestSslFileReadProcessed:
    def test_read_processed_ssl_rc4_full_appdata(
        self, testpcap, content_tls_appdata_all_plain
    ):
        with mount_pcap(
            testpcap,
            params=["--show-all", "-k", "{here}/keyfiles/ssl.key".format(here=HERE)],
        ) as mountpoint:
            files = get_file_list(mountpoint)
            assert "ssl/0-1838_SSL" in files
            with open(os.path.join(mountpoint, "ssl/0-1838_SSL"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_tls_appdata_all_plain

    def test_read_processed_ssl_as_http(
        self, testpcap, content_tls_appdata_all_plain_response_body_only
    ):
        with mount_pcap(
            testpcap,
            params=["--show-all", "-k", "{here}/keyfiles/ssl.key".format(here=HERE)],
        ) as mountpoint:
            files = get_file_list(mountpoint)
            assert "http/0-279" in files
            with open(os.path.join(mountpoint, "http/0-279"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_tls_appdata_all_plain_response_body_only


class TestConfigFile:
    def test_with_a_single_key_file(self, testpcap, expected_files_with_xor):
        with mount_pcap(
            testpcap,
            params=["-c", "{here}/configs/xor-with-key-file.toml".format(here=HERE)],
        ) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_xor


class TestIndex:
    def test_that_a_nonexisting_index_file_gets_written(self, testpcap):
        with empty_index_file() as index:
            with mount_pcap(
                testpcap,
                inmem=False,
                params=["--index={idx}".format(idx=index), "--no-mount"],
            ):
                assert os.path.isfile(index)
                assert os.path.getsize(index) > 0

    def test_that_an_empty_index_file_gets_overwritten(self, testpcap):
        with empty_index_file(create=True) as index:
            with mount_pcap(
                testpcap,
                inmem=False,
                params=["--index={idx}".format(idx=index), "--no-mount"],
            ):
                assert os.path.isfile(index)
                assert os.path.getsize(index) > 0


class TestFileContents:
    def test_dhcp_file(self, testpcap, content_dhcp_file):
        with mount_pcap(testpcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "dhcp/0-0_REQ-15645" in files
            with open(os.path.join(mountpoint, "dhcp/0-0_REQ-15645"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_dhcp_file

    def test_dns_file(self, testpcap, content_dns_file):
        with mount_pcap(testpcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "dns/2-0_REQ-28663" in files
            with open(os.path.join(mountpoint, "dns/2-0_REQ-28663"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_dns_file

    def test_ssh_file(self, testpcap, content_ssh_file):
        with mount_pcap(testpcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "ssh/11-2338_SSH-5" in files
            with open(os.path.join(mountpoint, "ssh/11-2338_SSH-5"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_ssh_file

    def test_http_file(self, testpcap, content_http_file):
        with mount_pcap(testpcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "http/2-312_headers" in files
            with open(os.path.join(mountpoint, "http/2-312_headers"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_http_file


@contextmanager
def mount_pcap(pcap, inmem=True, params=None):
    if params is None:
        params = list()
    if inmem:
        params.append("-m")
    with tempfile.TemporaryDirectory() as tmpdir:
        params.extend((pcap, tmpdir))
        cmd = ["pcapfs", *params]
        print(" ".join(cmd))
        try:
            subprocess.check_call(cmd)
            yield tmpdir
        finally:
            if "--no-mount" not in params and "-n" not in params:
                tries_left = 10
                try:
                    subprocess.check_call(["fusermount3", "-u", tmpdir])
                except OSError:
                    if tries_left == 0:
                        raise
                    tries_left -= 1


@contextmanager
def empty_index_file(create=False):
    index = generate_random_string(10)
    if create:
        open(index, "a").close()
    yield index
    try:
        os.remove(index)
    except FileNotFoundError:
        pass


def get_file_list(folder):
    files = list()
    for item in Path(folder).rglob("*"):
        if item.is_file():
            files.append(str(item.resolve()).split(folder + "/")[-1])
    return sorted(files)


def generate_random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


@pytest.fixture
def expected_files():
    return sorted(
        [
            "dhcp/0-0_REQ-15645",
            "dhcp/1-0_RES-15645",
            "dns/2-0_REQ-28663",
            "dns/2-28_RES-28663",
            "http/8-308_png",
            "http/7-311_jpeg",
            "http/6-309_json",
            "http/5-333_gzip",
            "http/4-339_deflate",
            "http/3-318_html",
            "http/2-312_headers",
            "http/1-306_ip",
            "ssh/11-2338_SSH-5",
            "ssh/11-2526_SSH-6",
            "ssl/0-1838_SSL",
            "tcp/0-135_tcp9",
            "tcp/0-143_tcp10",
        ]
    )


@pytest.fixture
def expected_files_with_xor(expected_files):
    expected_files.remove("tcp/0-143_tcp10")
    expected_files.append("xor/10-0_xor")
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove("ssl/0-1838_SSL")
    expected_files.append("http/0-279")
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = (
        "474554202f20485454502f312e310a"
        ""
        ""
        "484f53543a206c6f63616c686f73740a"
        ""
        ""
        "0a"
        ""
        ""
        "485454502f312e3120323030204f4b0d0a5365727665723a206e6769"
        "6e782f312e31302e3320285562756e7475290d0a446174653a205475652c"
        "2030342053657020323031382031343a34363a343820474d540d0a436f6e"
        "74656e742d547970653a20746578742f68746d6c0d0a436f6e74656e742d"
        "4c656e6774683a203631320d0a4c6173742d4d6f6469666965643a205475"
        "652c2030342053657020323031382031333a30363a313020474d540d0a43"
        "6f6e6e656374696f6e3a206b6565702d616c6976650d0a455461673a2022"
        "35623865383334322d323634220d0a4163636570742d52616e6765733a20"
        "62797465730d0a0d0a"
        ""
        "3c21444f43545950452068746d6c3e0a3c68746d6c"
        "3e0a3c686561643e0a3c7469746c653e57656c636f6d6520746f206e6769"
        "6e78213c2f7469746c653e0a3c7374796c653e0a20202020626f6479207b"
        "0a202020202020202077696474683a203335656d3b0a2020202020202020"
        "6d617267696e3a2030206175746f3b0a2020202020202020666f6e742d66"
        "616d696c793a205461686f6d612c2056657264616e612c20417269616c2c"
        "2073616e732d73657269663b0a202020207d0a3c2f7374796c653e0a3c2f"
        "686561643e0a3c626f64793e0a3c68313e57656c636f6d6520746f206e67"
        "696e78213c2f68313e0a3c703e496620796f752073656520746869732070"
        "6167652c20746865206e67696e7820776562207365727665722069732073"
        "75636365737366756c6c7920696e7374616c6c656420616e640a776f726b"
        "696e672e204675727468657220636f6e66696775726174696f6e20697320"
        "72657175697265642e3c2f703e0a0a3c703e466f72206f6e6c696e652064"
        "6f63756d656e746174696f6e20616e6420737570706f727420706c656173"
        "6520726566657220746f0a3c6120687265663d22687474703a2f2f6e6769"
        "6e782e6f72672f223e6e67696e782e6f72673c2f613e2e3c62722f3e0a43"
        "6f6d6d65726369616c20737570706f727420697320617661696c61626c65"
        "2061740a3c6120687265663d22687474703a2f2f6e67696e782e636f6d2f"
        "223e6e67696e782e636f6d3c2f613e2e3c2f703e0a0a3c703e3c656d3e54"
        "68616e6b20796f7520666f72207573696e67206e67696e782e3c2f656d3e"
        "3c2f703e0a3c2f626f64793e0a3c2f68746d6c3e0a"
    )
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_plain_response_body_only():
    content_tls_appdata_all_plain_response_body_only = (
        ""
        "3c21444f43545950452068746d6c3e0a3c68746d6c"
        "3e0a3c686561643e0a3c7469746c653e57656c636f6d6520746f206e6769"
        "6e78213c2f7469746c653e0a3c7374796c653e0a20202020626f6479207b"
        "0a202020202020202077696474683a203335656d3b0a2020202020202020"
        "6d617267696e3a2030206175746f3b0a2020202020202020666f6e742d66"
        "616d696c793a205461686f6d612c2056657264616e612c20417269616c2c"
        "2073616e732d73657269663b0a202020207d0a3c2f7374796c653e0a3c2f"
        "686561643e0a3c626f64793e0a3c68313e57656c636f6d6520746f206e67"
        "696e78213c2f68313e0a3c703e496620796f752073656520746869732070"
        "6167652c20746865206e67696e7820776562207365727665722069732073"
        "75636365737366756c6c7920696e7374616c6c656420616e640a776f726b"
        "696e672e204675727468657220636f6e66696775726174696f6e20697320"
        "72657175697265642e3c2f703e0a0a3c703e466f72206f6e6c696e652064"
        "6f63756d656e746174696f6e20616e6420737570706f727420706c656173"
        "6520726566657220746f0a3c6120687265663d22687474703a2f2f6e6769"
        "6e782e6f72672f223e6e67696e782e6f72673c2f613e2e3c62722f3e0a43"
        "6f6d6d65726369616c20737570706f727420697320617661696c61626c65"
        "2061740a3c6120687265663d22687474703a2f2f6e67696e782e636f6d2f"
        "223e6e67696e782e636f6d3c2f613e2e3c2f703e0a0a3c703e3c656d3e54"
        "68616e6b20796f7520666f72207573696e67206e67696e782e3c2f656d3e"
        "3c2f703e0a3c2f626f64793e0a3c2f68746d6c3e0a"
    )
    return content_tls_appdata_all_plain_response_body_only


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = (
        "0193362a0c21d85d0e6b8b4152e68603df80bd0a4a3f5b657d88fdb100ba"
        "78b8bbb51ff1f8fea5fb102bfecaa32d0a397e5365a00d117cb0c14cfa1f"
        "16018b53deb3f534b6a08b3d0adb5a284bd5120cce38e1b771dbb8b5d70d"
        "ef1be64ac61d92d299a2909f35300628cccef3612ebdaa79f48713ee4835"
        "e8017175661c5af44497a65c15130f1ae6674ce274b49d14bb050a01c4a2"
        "ccdc4de05d18351cd458b3f3cc7f6d872ec170740ee599bba7aa5c6eaa58"
        "40f8dd82e4ccca29bae993ecc3a4720b4b66d13fbe1ab0a5f59ded31bfbc"
        "adbd8681177161710a62558e762bc0bd48ce3c12eb1aae11196bb351fa9e"
        "e6855ebf95b8770d7dcca7c687c83f1565f702478409799b6c6ba3dcd220"
        "28fe404d21e568f187d8f4f824e6297b8a1544f06fd2966e750e6feb4086"
        "7fd66656e49aac5b7dbb17b3925e1a09a1551cea64ef9523ac76fc059b32"
        "03c894a156f9347aedc67a5abf880fb8e12add50242f359cdfcd5cbe304c"
        "24a7fb480a9ad5963767a16385dd2bae363932a3495e9cd27ad272542683"
        "a6cf0933096f10b6281a17ef1fb1f8037d91799a08701a6e9cc6338e3bae"
        "e8528a6f4b30542c46c2a44dde615b131abb448bb50a12af539e008b6516"
        "4c56eb6a2751da9dd3d25a87bb17ab83b6f19df684a10281706a7abc87f5"
        "dcc2bbfb3848a409ea570b276610e54c0d358136cb1e936ac24a2018252b"
        "d3beb8f8ef9035ef4e51e1867f21f29fa5550a3db5cc16ea86c6d629b444"
        "2bb138a1e81aa6930e63dcb82626d68050bf6805c32308d27cb7d3b5a004"
        "5029b47dbac9aeb38f0b2f26c4001db15aa93ad79972d557ef4308692283"
        "fb976202667e056debbf75eb0d7a7c3c76edfd8e84c6e4800125184648d6"
        "80e5ec59947daa18745a2f15281f986483aed0c9b547df01325569c08500"
        "11a0f0154529985869de5e748bd460154bd014bf57503f336a3920c48453"
        "dd01d507868920656a54eb3c4aaf96beaf6a8f28bdc20523d7ed95612e9a"
        "b0c745b0aff3139c0a3da7962cce2773e7e55dc4638c4419d0332af45565"
        "289c7c9b751156328b3a49c59f0e4614d2ea460550f1865a41bbb70acab8"
        "5292b2da21c813ff42906ec8147ba6473af102c212c2232574f51184989b"
        "0b6aad9e26137e07d85489780b5028006cc24663ebac1f753676a0c6fe93"
        "4e8d2a8a03ff4d4ca3dfdc69978160bbeffe8b7c29f229942c7f3d572a49"
        "afbcb07efcac97515fdee9dc4d2ecc01de8ccd2650ee9120fe54868da196"
        "8ce58be61d5e9d9c1ab3cb38881ea2783b16cec9b810df28ea543ee6aee6"
        "b1132298bf5c9f550077c7e7eb47c83bfb2ade39e02319de96"
    )
    return content_tls_appdata_all_cipher


@pytest.fixture
def content_dhcp_file():
    content_dhcp_file = (
        "7b0a0922426f6f742046696c65204e616d65223a2022222c0a0922436c69"
        "656e742049502041646472657373223a2022302e302e302e30222c0a0922"
        "436c69656e74204d41432041646472657373223a202230303a30623a3832"
        "3a30313a66633a3432222c0a09224944223a20223135363435222c0a0922"
        "4e657874205365727665722049502041646472657373223a2022302e302e"
        "302e30222c0a09224f7074696f6e73223a207b0a090922436c69656e7420"
        "4964656e746966696572223a207b0a09090922436c69656e74204d414320"
        "41646472657373223a202230303a30623a38323a30313a66633a3432222c"
        "0a0909092248617264776172652054797065223a202245746865726e6574"
        "220a09097d2c0a09092244484350204d6573736167652054797065223a20"
        "224448435020446973636f766572222c0a090922506172616d6574657220"
        "52657175657374204c697374223a205b0a090909225375626e6574204d61"
        "736b222c0a09090922526f75746572222c0a09090922444e532053657276"
        "657273222c0a090909224e54502053657276657220416464726573736573"
        "220a09095d2c0a0909225265717565737465642049502041646472657373"
        "223a2022302e302e302e30220a097d2c0a092252656c6179204167656e74"
        "2049502041646472657373223a2022302e302e302e30222c0a0922536572"
        "76657220486f7374204e616d65223a2022222c0a0922596f757220495020"
        "41646472657373223a2022302e302e302e30220a7d"
    )
    return content_dhcp_file


@pytest.fixture
def content_dns_file():
    content_dns_file = (
        "7b0a09224944223a20223238363633222c0a092251756572696573223a20"
        "5b0a09097b0a09090922636c617373223a2022494e222c0a090909226e61"
        "6d65223a2022676f6f676c652e636f6d222c0a0909092274797065223a20"
        "224d58220a09097d0a095d0a7d"
    )
    return content_dns_file


@pytest.fixture
def content_ssh_file():
    content_ssh_file = (
        "79e5cae3b9834cdf17fe31258d4e6c436c197199b1f856b0cd2cbbac3551"
        "fc1b95476d45600ee3f84738819ec925011dfea1385f3324a99dec57c1db"
        "ee0ecb9c6f07024fdfd83ba087467b44742eac589cd7b5b2a1dfb3fd8494"
        "fd4088b5a8c420e032808e7fae38f260122939ae28a58342bd87b71df5eb"
        "5c29626a62d352b7c4e9551b1ec9afffa0788157820cb54e27083acb54a4"
        "3b273b19e85708bf33dde1292911f0d6b91d8ec37a73"
    )
    return content_ssh_file


@pytest.fixture
def content_http_file():
    content_http_file = (
        "7b0a20202268656164657273223a207b0a2020202022416363657074223a"
        "20222a2f2a222c200a2020202022486f7374223a20227365727665722e74"
        "657374222c200a2020202022557365722d4167656e74223a20226375726c"
        "2f372e36312e31220a20207d0a7d0a"
    )
    return content_http_file
