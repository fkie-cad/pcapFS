#!/usr/bin/env python3
import os
import random
import string
import subprocess
import tempfile
from contextlib import contextmanager

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))


class TestXor:

    def test_with_single_xor_key_file(self, test_pcap, expected_files_with_xor):
        with mount_pcap(test_pcap, params=['-c', '{here}/configs/xor.toml'.format(here=HERE),
                                           '-k', '{here}/keyfiles/xor.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_xor
            with open(os.path.join(mountpoint, 'xor/10-0_xor')) as f:
                assert f.read() == 'pcapFStest'


class TestSsl:

    def test_with_single_ssl_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/ssl.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'system-tests.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/8-308_png', 'http/7-311_jpeg', 'http/6-309_json', 'http/5-333_gzip', 'http/4-339_deflate',
                   'http/3-318_html', 'http/2-312_headers', 'http/1-306_ip', 'ssl/0-1838_SSL',
                   'tcp/0-131_tcp9', 'tcp/0-139_tcp10'])


@pytest.fixture
def expected_files_with_xor(expected_files):
    expected_files.remove('tcp/0-139_tcp10')
    expected_files.append('xor/10-0_xor')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('ssl/0-1838_SSL')
    expected_files.append('http/0-279')
    return sorted(expected_files)
