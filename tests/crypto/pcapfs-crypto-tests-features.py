#!/usr/bin/env python3
import os
import subprocess
import tempfile
from contextlib import contextmanager

import pytest

"""
test decryption with master secret, premaster secret, private server key and
tls certificate extraction for separate tls connections in one pcap
"""

HERE = os.path.dirname(os.path.realpath(__file__))


class TestCryptoFeatures:
    def test_features(self, test_pcap, expected_files):
        with mount_pcap(
            test_pcap,
            params=[
                "-k",
                "{here}/feature_test/keyfiles".format(here=HERE),
                "--show-metadata",
            ],
        ) as mountpoint:
            files = get_file_list(mountpoint)
            assert files == expected_files
            for file in files:
                f = open(os.path.join(mountpoint, file), "rb")
                f_cmp = open(
                    os.path.join(
                        "{here}/feature_test/expected_output".format(here=HERE), file
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
        os.path.dirname(os.path.realpath(__file__)), "feature_test/feature_test.pcap"
    )


@pytest.fixture
def expected_files():
    return sorted(
        [
            "http/4-0_GET.meta",
            "http/4-117",
            "http/4-73.meta",
            "tls/0-626_TLSCertificate.pem",
            "tls/1-1726_TLS",
            "tls/1-193_TLSCertificate.pem",
            "tls/2-1624_TLS",
            "tls/2-195_TLSCertificate.pem",
        ]
    )
