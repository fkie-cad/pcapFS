#!/usr/bin/env python3
import os
import subprocess
import tempfile
from contextlib import contextmanager

import pytest

"""
test ssl decryption with all supported ciphers
"""

HERE = os.path.dirname(os.path.realpath(__file__))


class TestAllCiphers:
    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            files = get_file_list(mountpoint)
            assert files == expected_files_with_ssl_nokey
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

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(
            test_pcap,
            params=[
                "-k",
                "{here}/all_ciphers_test/all_ciphers.key".format(here=HERE),
            ],
        ) as mountpoint:
            files = get_file_list(mountpoint)
            assert files == expected_files_with_ssl
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
def expected_files_with_ssl_nokey():
    return sorted(
        [
            "ssl/0-1838_SSL",
            "ssl/10-2218_SSL",
            "ssl/11-2218_SSL",
            "ssl/12-1624_SSL",
            "ssl/1-2758_SSL",
            "ssl/13-942_SSL",
            "ssl/14-866_SSL",
            "ssl/15-1710_SSL",
            "ssl/16-2504_SSL",
            "ssl/17-2504_SSL",
            "ssl/18-966_SSL",
            "ssl/19-1734_SSL",
            "ssl/20-2420_SSL",
            "ssl/21-2420_SSL",
            "ssl/2-1726_SSL",
            "ssl/22-882_SSL",
            "ssl/23-1650_SSL",
            "ssl/24-1736_SSL",
            "ssl/25-582_SSL",
            "ssl/26-650_SSL",
            "ssl/27-650_SSL",
            "ssl/28-1828_SSL",
            "ssl/29-1860_SSL",
            "ssl/30-2528_SSL",
            "ssl/3-2095_SSL",
            "ssl/4-1726_SSL",
            "ssl/5-2078_SSL",
            "ssl/6-2047_SSL",
            "ssl/7-2883_SSL",
            "ssl/8-2064_SSL",
            "ssl/9-2168_SSL",
        ]
    )


@pytest.fixture
def expected_files_with_ssl():
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
            "ssl/12-1624_SSL",
            "ssl/13-942_SSL",
            "ssl/14-866_SSL",
            "ssl/15-1710_SSL",
            "ssl/16-2504_SSL",
            "ssl/17-2504_SSL",
            "ssl/18-966_SSL",
            "ssl/19-1734_SSL",
            "ssl/20-2420_SSL",
            "ssl/21-2420_SSL",
            "ssl/2-1726_SSL",
            "ssl/22-882_SSL",
            "ssl/23-1650_SSL",
            "ssl/24-1736_SSL",
            "ssl/25-582_SSL",
            "ssl/26-650_SSL",
            "ssl/27-650_SSL",
            "ssl/28-1828_SSL",
            "ssl/29-1860_SSL",
            "ssl/30-2528_SSL",
            "ssl/4-1726_SSL",
        ]
    )
