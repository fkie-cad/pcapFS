#!/usr/bin/env python3
import os
import subprocess
import tempfile
from contextlib import contextmanager

import pytest

"""
test tls decryption with all supported ciphers
"""

HERE = os.path.dirname(os.path.realpath(__file__))


class TestAllCiphers:
    def test_without_key_file(self, test_pcap, expected_files_with_tls_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert files == expected_files_with_tls_nokey
            for file in files:
                f = open(os.path.join(mountpoint, file), "rb")
                f_cmp = open(
                    os.path.join(
                        "{here}/all_ciphers_test/expected_output/raw".format(here=HERE),
                        file,
                    ),
                    "rb",
                )
                assert f.read() == f_cmp.read()
                f.close()
                f_cmp.close()

    def test_with_key_file(self, test_pcap, expected_files_with_tls):
        with mount_pcap(
            test_pcap,
            params=[
                "-k",
                "{here}/all_ciphers_test/all_ciphers.key".format(here=HERE),
            ],
        ) as mountpoint:
            files = get_file_list(mountpoint)
            assert files == expected_files_with_tls
            for file in files:
                f = open(os.path.join(mountpoint, file), "rb")
                f_cmp = open(
                    os.path.join(
                        "{here}/all_ciphers_test/expected_output/decrypted".format(
                            here=HERE
                        ),
                        file,
                    ),
                    "rb",
                )
                assert f.read() == f_cmp.read()
                f.close()
                f_cmp.close()


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


def get_file_list(folder):
    files = list()
    for d in os.listdir(folder):
        files.extend(os.path.join(d, f) for f in os.listdir(os.path.join(folder, d)))
    return sorted(files)


@pytest.fixture
def test_pcap():
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "all_ciphers_test/all_ciphers.pcap"
    )


@pytest.fixture
def expected_files_with_tls_nokey():
    return sorted(
        [
            "tls/0-1838_TLS",
            "tls/10-2218_TLS",
            "tls/11-2218_TLS",
            "tls/12-1624_TLS",
            "tls/1-2758_TLS",
            "tls/13-942_TLS",
            "tls/14-866_TLS",
            "tls/15-1710_TLS",
            "tls/16-2504_TLS",
            "tls/17-2504_TLS",
            "tls/18-966_TLS",
            "tls/19-1734_TLS",
            "tls/20-2420_TLS",
            "tls/21-2420_TLS",
            "tls/2-1726_TLS",
            "tls/22-882_TLS",
            "tls/23-1650_TLS",
            "tls/24-1736_TLS",
            "tls/25-582_TLS",
            "tls/26-650_TLS",
            "tls/27-650_TLS",
            "tls/28-1828_TLS",
            "tls/29-1860_TLS",
            "tls/30-2528_TLS",
            "tls/3-2095_TLS",
            "tls/4-1726_TLS",
            "tls/5-2078_TLS",
            "tls/6-2047_TLS",
            "tls/7-2883_TLS",
            "tls/8-2064_TLS",
            "tls/9-2168_TLS",
        ]
    )


@pytest.fixture
def expected_files_with_tls():
    return sorted(
        [
            "http/0-483",
            "http/13-483",
            "http/15-117",
            "http/2-483",
            "http/35-483",
            "http/39-483",
            "http/43-279",
            "http/5-483",
            "http/7-483",
            "http/9-483",
            "tls/12-1624_TLS",
            "tls/13-942_TLS",
            "tls/14-866_TLS",
            "tls/15-1710_TLS",
            "tls/16-2504_TLS",
            "tls/17-2504_TLS",
            "tls/18-966_TLS",
            "tls/19-1734_TLS",
            "tls/20-2420_TLS",
            "tls/21-2420_TLS",
            "tls/2-1726_TLS",
            "tls/22-882_TLS",
            "tls/23-1650_TLS",
            "tls/24-1736_TLS",
            "tls/25-582_TLS",
            "tls/26-650_TLS",
            "tls/27-650_TLS",
            "tls/28-1828_TLS",
            "tls/29-1860_TLS",
            "tls/30-2528_TLS",
            "tls/4-1726_TLS",
        ]
    )
