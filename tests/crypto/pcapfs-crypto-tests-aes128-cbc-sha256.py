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

class TestAes128CbcSha256:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes128-cbc-sha256.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-1726_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-1726_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes128-cbc-sha256.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-1726_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-1726_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_plain)


@contextmanager
def mount_pcap(pcap, inmem=True, params=None):
    if params is None:
        params = list()
    if inmem:
        params.append('-m')
    with tempfile.TemporaryDirectory() as tmpdir:
        params.extend((pcap, tmpdir))
        cmd = ['pcapfs', *params]
        print(' '.join(cmd))
        try:
            subprocess.check_call(cmd)
            yield tmpdir
        finally:
            if '--no-mount' not in params and '-n' not in params:
                tries_left = 10
                try:
                    subprocess.check_call(['fusermount3', '-u', tmpdir])
                except OSError:
                    if tries_left == 0:
                        raise
                    tries_left -= 1


@contextmanager
def empty_index_file(create=False):
    index = generate_random_string(10)
    if create:
        open(index, 'a').close()
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
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


@pytest.fixture
def test_pcap():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes128-cbc-sha256.pcap')


@pytest.fixture
def expected_files():
    return sorted(['ssl/0-1726_SSL', 'tcp/0-4_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = "68656c6c6f207468657265210a6865790a676f74746120676f2c20627965210a63750a"
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "fbe3f42cf1ccfdac9bcf8b4e09e5ef6bdffbae5d80c01cd3ab9597536d0f5926" \
                                    "aaf1b9db6c8218635297a6185270b8ac8e73a6fbb22299499b3cdd11f007ab59" \
                                    "1fff18a45af21993cfed2846c1d4e97a5d3c5c8e7e4446ae215f8b3f49a936b1" \
                                    "c09b03a66325471d28279048b18204adb3899e01d4a1fea4ca8515af61ced979" \
                                    "6f0c3471d84cf7e2873e82f133d880656ac5e1ac9267269756e756118aeaf8c0" \
                                    "ea8875ed12c6e6b50f543700a7b46927c3fbcccba10af5896999461c8ec612da" \
                                    "3364d44d5560ef563353d1193b97bab33ff7a7c7f745069540986ddca0fc7441" \
                                    "287325eba03cec4369617b79da938f4882bd77825eae490675c4b695ee565565" 
    return content_tls_appdata_all_cipher
