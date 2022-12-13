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

class TestAes256CbcSha256:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes256-cbc-sha256.key'.format(here=HERE)]) as mountpoint:
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
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes256-cbc-sha256.key'.format(here=HERE)]) as mountpoint:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes256-cbc-sha256.pcap')


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
    content_tls_appdata_all_cipher = "6802793d4e1f0dce00b7e2e477fc39e0e8b7d0c03cd12b49ce3b77856d990b56" \
                                    "2aa5b95817527e06783c9a3b0aa77e26aa6a13e60bcc451c837d797a1f1889b8" \
                                    "8f27ffff8bd944f64b3cfca3ba03746301e9da1e54bd60c20b6f83ae2f56fd32" \
                                    "4ca45c4d6116edad5789f0b4183dd5fdb15f45a4c0d7d013af1175bbbbd07a6c" \
                                    "e8929f3796b4fcf2d96d5550240677a9d6c967c28a56c5409d4d475e467a1ba0" \
                                    "9fe1a50885f65b3d987d6912b7bb84ac3477b762ab0ffc560b26c531db50f6fb" \
                                    "752832992aa56d05725cc60844642a3676dda1e035e331d999236cd5c84cb914" \
                                    "17ae8ba0d7c102eecf458041442bf47d8e855285d1591399da81be3fd029e513" 
    return content_tls_appdata_all_cipher