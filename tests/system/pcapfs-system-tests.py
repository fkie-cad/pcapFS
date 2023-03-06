#!/usr/bin/env python3
import os
import random
import string
import subprocess
import tempfile
import binascii
from contextlib import contextmanager

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))


class TestBasicFunctionality:
    def test_pcap_gets_mounted(self, test_pcap):
        with mount_pcap(test_pcap) as mountpoint:
            assert os.path.ismount(mountpoint)

    def test_mount_point_is_not_empty(self, test_pcap):
        with mount_pcap(test_pcap) as mountpoint:
            assert len(os.listdir(mountpoint)) > 0

    def test_mount_point_contains_all_directories(self, test_pcap):
        with mount_pcap(test_pcap) as mountpoint:
            assert os.listdir(mountpoint) == ["http", "ssl", "tcp"]

    def test_mount_point_contains_all_files(self, test_pcap, expected_files):
        with mount_pcap(test_pcap) as mountpoint:
            files = list()
            for d in ["http", "ssl", "tcp"]:
                files.extend(
                    os.path.join(d, f) for f in os.listdir(os.path.join(mountpoint, d))
                )
        assert sorted(files) == expected_files


class TestSortByOption:
    def test_src_port(self, test_pcap):
        expected_files = (
            "12345/0-131_tcp9",
            "443/0-1838_SSL",
            "52218/1-306_ip",
            "52220/2-312_headers",
            "52222/3-318_html",
            "52226/4-339_deflate",
            "52228/5-333_gzip",
            "52230/6-309_json",
            "52236/7-311_jpeg",
            "52240/8-308_png",
            "54321/0-139_tcp10",
        )
        with mount_pcap(test_pcap, params=["--sortby=dstPort"]) as mountpoint:
            assert get_file_list(mountpoint) == sorted(expected_files)


class TestXor:
    def test_with_single_xor_key_file(self, test_pcap, expected_files_with_xor):
        with mount_pcap(
            test_pcap,
            params=[
                "-c",
                "{here}/configs/xor.toml".format(here=HERE),
                "-k",
                "{here}/keyfiles/xor.key".format(here=HERE),
            ],
        ) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_xor
            with open(os.path.join(mountpoint, "xor/10-0_xor")) as f:
                assert f.read() == "pcapFStest"


class TestSsl:
    def test_with_single_ssl_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(
            test_pcap, params=["-k", "{here}/keyfiles/ssl.key".format(here=HERE)]
        ) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


class TestSslFileReadRaw:
    def test_read_raw_ssl_rc4_full_appdata(
        self, test_pcap, content_tls_appdata_all_cipher
    ):
        with mount_pcap(test_pcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert "ssl/0-1838_SSL" in files
            with open(os.path.join(mountpoint, "ssl/0-1838_SSL"), "rb") as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, "UTF-8")
                assert hexdata == content_tls_appdata_all_cipher


class TestSslFileReadProcessed:
    def test_read_processed_ssl_rc4_full_appdata(
        self, test_pcap, content_tls_appdata_all_plain
    ):
        with mount_pcap(
            test_pcap,
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
        self, test_pcap, content_tls_appdata_all_plain_response_body_only
    ):
        with mount_pcap(
            test_pcap,
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
    def test_with_a_single_key_file(self, test_pcap, expected_files_with_xor):
        with mount_pcap(
            test_pcap,
            params=["-c", "{here}/configs/xor-with-key-file.toml".format(here=HERE)],
        ) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_xor


class TestIndex:
    def test_that_a_nonexisting_index_file_gets_written(self, test_pcap):
        with empty_index_file() as index:
            with mount_pcap(
                test_pcap,
                inmem=False,
                params=["--index={idx}".format(idx=index), "--no-mount"],
            ):
                assert os.path.isfile(index)
                assert os.path.getsize(index) > 0

    def test_that_an_empty_index_file_gets_overwritten(self, test_pcap):
        with empty_index_file(create=True) as index:
            with mount_pcap(
                test_pcap,
                inmem=False,
                params=["--index={idx}".format(idx=index), "--no-mount"],
            ):
                assert os.path.isfile(index)
                assert os.path.getsize(index) > 0


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
    for d in os.listdir(folder):
        files.extend(os.path.join(d, f) for f in os.listdir(os.path.join(folder, d)))
    return sorted(files)


def generate_random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


@pytest.fixture
def test_pcap():
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "system-tests.pcap"
    )


@pytest.fixture
def expected_files():
    return sorted(
        [
            "http/8-308_png",
            "http/7-311_jpeg",
            "http/6-309_json",
            "http/5-333_gzip",
            "http/4-339_deflate",
            "http/3-318_html",
            "http/2-312_headers",
            "http/1-306_ip",
            "ssl/0-1838_SSL",
            "tcp/0-131_tcp9",
            "tcp/0-139_tcp10",
        ]
    )


@pytest.fixture
def expected_files_with_xor(expected_files):
    expected_files.remove("tcp/0-139_tcp10")
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
        "0193362a0c21d85d0e6b8b4152e68603df80bd0a4a3f5b657d88fdb100ba78"
        ""
        "b8bbb51ff1f8fea5fb102bfecaa32d0a397e5365a00d117cb0c14cfa1f16018b"
        ""
        "53deb3f534b6a08b3d0adb5a284bd5120c"
        ""
        "ce38e1b771dbb8b5d70def1be64ac61d92d299a2909f35300628cccef3612ebdaa79f48713ee4835e8017175661c5af44497a65c15130f1ae6674ce274b49d14bb050a01c4a2ccdc4de05d18351cd458b3f3cc7f6d872ec170740ee599bba7aa5c6eaa5840f8dd82e4ccca29bae993ecc3a4720b4b66d13fbe1ab0a5f59ded31bfbcadbd8681177161710a62558e762bc0bd48ce3c12eb1aae11196bb351fa9ee6855ebf95b8770d7dcca7c687c83f1565f702478409799b6c6ba3dcd22028fe404d21e568f187d8f4f824e6297b8a1544f06fd2966e750e6feb40867fd66656e49aac5b7dbb17b3925e1a09a1551cea64ef9523ac76fc059b3203c894a156f9347aedc67a5abf880fb8e12add50242f359cdfcd5cbe304c24a7fb480a9ad5963767a16385dd2bae363932a3495e9cd27ad272542683a6cf0933096f10b6281a17ef1fb1f8037d91799a08701a6e9cc6338e3baee8528a6f4b30542c46c2a44dde615b131abb448bb50a12af539e008b65164c56eb6a2751da9dd3d25a87bb17ab83b6f19df684a10281706a7abc87f5dcc2bbfb3848a409ea570b276610e54c0d358136cb1e936ac24a2018252bd3beb8f8ef9035ef4e51e1867f21f29fa5550a3db5cc16ea86c6d629b4442bb138a1e81aa6930e63dcb82626d68050bf6805c32308d27cb7d3b5a0045029b47dbac9aeb38f0b2f26c4001db15aa93ad79972d557ef4308692283fb976202667e056debbf75eb0d7a7c3c76edfd8e84c6e4800125184648d680e5ec59947daa18745a2f15281f986483aed0c9b547df01325569c0850011a0f0154529985869de5e748bd460154bd014bf57503f336a3920c48453dd01d507868920656a54eb3c4aaf96beaf6a8f28bdc20523d7ed95612e9ab0c745b0aff3139c0a3da7962cce2773e7e55dc4638c4419d0332af45565289c7c9b751156328b3a49c59f0e4614d2ea460550f1865a41bbb70acab85292b2da21c813ff42906ec8147ba6473af102c212c2232574f51184989b0b6aad9e26137e07d85489780b5028006cc24663ebac1f753676a0c6fe934e8d2a8a03ff4d4ca3dfdc69978160bbeffe8b7c29f229942c7f3d572a49afbcb07efcac97515fdee9dc4d2ecc01de8ccd2650ee9120fe54868da1968ce58be61d5e9d9c1ab3cb38881ea2783b16cec9b810df28ea543ee6aee6b1132298bf5c9f550077c7e7eb47c83bfb2ade39e02319de96"
    )
    return content_tls_appdata_all_cipher
