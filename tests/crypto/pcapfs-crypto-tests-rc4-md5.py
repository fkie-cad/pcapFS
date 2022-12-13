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

class TestRc4Md5:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/rc4-md5.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-1838_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-1838_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/rc4-md5.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-1838_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-1838_SSL'), 'rb') as f:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/rc4-md5.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/0-279', 'ssl/0-1838_SSL', 'tcp/0-1_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-1_tcp0')
    expected_files.remove('http/0-279')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-1_tcp0')
    expected_files.remove('ssl/0-1838_SSL')
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "0193362a0c21d85d0e6b8b4152e68603df80bd0a4a3f5b657d88fdb100ba78b8" \
                                    "bbb51ff1f8fea5fb102bfecaa32d0a397e5365a00d117cb0c14cfa1f16018b53" \
                                    "deb3f534b6a08b3d0adb5a284bd5120cce38e1b771dbb8b5d70def1be64ac61d" \
                                    "92d299a2909f35300628cccef3612ebdaa79f48713ee4835e8017175661c5af4" \
                                    "4497a65c15130f1ae6674ce274b49d14bb050a01c4a2ccdc4de05d18351cd458" \
                                    "b3f3cc7f6d872ec170740ee599bba7aa5c6eaa5840f8dd82e4ccca29bae993ec" \
                                    "c3a4720b4b66d13fbe1ab0a5f59ded31bfbcadbd8681177161710a62558e762b" \
                                    "c0bd48ce3c12eb1aae11196bb351fa9ee6855ebf95b8770d7dcca7c687c83f15" \
                                    "65f702478409799b6c6ba3dcd22028fe404d21e568f187d8f4f824e6297b8a15" \
                                    "44f06fd2966e750e6feb40867fd66656e49aac5b7dbb17b3925e1a09a1551cea" \
                                    "64ef9523ac76fc059b3203c894a156f9347aedc67a5abf880fb8e12add50242f" \
                                    "359cdfcd5cbe304c24a7fb480a9ad5963767a16385dd2bae363932a3495e9cd2" \
                                    "7ad272542683a6cf0933096f10b6281a17ef1fb1f8037d91799a08701a6e9cc6" \
                                    "338e3baee8528a6f4b30542c46c2a44dde615b131abb448bb50a12af539e008b" \
                                    "65164c56eb6a2751da9dd3d25a87bb17ab83b6f19df684a10281706a7abc87f5" \
                                    "dcc2bbfb3848a409ea570b276610e54c0d358136cb1e936ac24a2018252bd3be" \
                                    "b8f8ef9035ef4e51e1867f21f29fa5550a3db5cc16ea86c6d629b4442bb138a1" \
                                    "e81aa6930e63dcb82626d68050bf6805c32308d27cb7d3b5a0045029b47dbac9" \
                                    "aeb38f0b2f26c4001db15aa93ad79972d557ef4308692283fb976202667e056d" \
                                    "ebbf75eb0d7a7c3c76edfd8e84c6e4800125184648d680e5ec59947daa18745a" \
                                    "2f15281f986483aed0c9b547df01325569c0850011a0f0154529985869de5e74" \
                                    "8bd460154bd014bf57503f336a3920c48453dd01d507868920656a54eb3c4aaf" \
                                    "96beaf6a8f28bdc20523d7ed95612e9ab0c745b0aff3139c0a3da7962cce2773" \
                                    "e7e55dc4638c4419d0332af45565289c7c9b751156328b3a49c59f0e4614d2ea" \
                                    "460550f1865a41bbb70acab85292b2da21c813ff42906ec8147ba6473af102c2" \
                                    "12c2232574f51184989b0b6aad9e26137e07d85489780b5028006cc24663ebac" \
                                    "1f753676a0c6fe934e8d2a8a03ff4d4ca3dfdc69978160bbeffe8b7c29f22994" \
                                    "2c7f3d572a49afbcb07efcac97515fdee9dc4d2ecc01de8ccd2650ee9120fe54" \
                                    "868da1968ce58be61d5e9d9c1ab3cb38881ea2783b16cec9b810df28ea543ee6" \
                                    "aee6b1132298bf5c9f550077c7e7eb47c83bfb2ade39e02319de96"
    return content_tls_appdata_all_cipher


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = "474554202f20485454502f312e310a484f53543a206c6f63616c686f73740a0a" \
                                    "485454502f312e3120323030204f4b0d0a5365727665723a206e67696e782f31" \
                                    "2e31302e3320285562756e7475290d0a446174653a205475652c203034205365" \
                                    "7020323031382031343a34363a343820474d540d0a436f6e74656e742d547970" \
                                    "653a20746578742f68746d6c0d0a436f6e74656e742d4c656e6774683a203631" \
                                    "320d0a4c6173742d4d6f6469666965643a205475652c20303420536570203230" \
                                    "31382031333a30363a313020474d540d0a436f6e6e656374696f6e3a206b6565" \
                                    "702d616c6976650d0a455461673a202235623865383334322d323634220d0a41" \
                                    "63636570742d52616e6765733a2062797465730d0a0d0a3c21444f4354595045" \
                                    "2068746d6c3e0a3c68746d6c3e0a3c686561643e0a3c7469746c653e57656c63" \
                                    "6f6d6520746f206e67696e78213c2f7469746c653e0a3c7374796c653e0a2020" \
                                    "2020626f6479207b0a202020202020202077696474683a203335656d3b0a2020" \
                                    "2020202020206d617267696e3a2030206175746f3b0a2020202020202020666f" \
                                    "6e742d66616d696c793a205461686f6d612c2056657264616e612c2041726961" \
                                    "6c2c2073616e732d73657269663b0a202020207d0a3c2f7374796c653e0a3c2f" \
                                    "686561643e0a3c626f64793e0a3c68313e57656c636f6d6520746f206e67696e" \
                                    "78213c2f68313e0a3c703e496620796f7520736565207468697320706167652c" \
                                    "20746865206e67696e7820776562207365727665722069732073756363657373" \
                                    "66756c6c7920696e7374616c6c656420616e640a776f726b696e672e20467572" \
                                    "7468657220636f6e66696775726174696f6e2069732072657175697265642e3c" \
                                    "2f703e0a0a3c703e466f72206f6e6c696e6520646f63756d656e746174696f6e" \
                                    "20616e6420737570706f727420706c6561736520726566657220746f0a3c6120" \
                                    "687265663d22687474703a2f2f6e67696e782e6f72672f223e6e67696e782e6f" \
                                    "72673c2f613e2e3c62722f3e0a436f6d6d65726369616c20737570706f727420" \
                                    "697320617661696c61626c652061740a3c6120687265663d22687474703a2f2f" \
                                    "6e67696e782e636f6d2f223e6e67696e782e636f6d3c2f613e2e3c2f703e0a0a" \
                                    "3c703e3c656d3e5468616e6b20796f7520666f72207573696e67206e67696e78" \
                                    "2e3c2f656d3e3c2f703e0a3c2f626f64793e0a3c2f68746d6c3e0a" 
    return content_tls_appdata_all_plain
