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

class TestAes256CbcSha:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes256-cbc-sha.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2095_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2095_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes256-cbc-sha.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2095_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2095_SSL'), 'rb') as f:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes256-cbc-sha.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/0-483', 'ssl/0-2095_SSL', 'tcp/0-4_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('http/0-483')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('ssl/0-2095_SSL')
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = "474554202f20485454502f312e310d0a486f73743a206c6f63616c686f73740d" \
                                    "0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b2055" \
                                    "62756e74753b204c696e7578207838365f36343b2072763a3130372e30292047" \
                                    "65636b6f2f32303130303130312046697265666f782f3130372e300d0a416363" \
                                    "6570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c" \
                                    "2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d616765" \
                                    "2f617669662c696d6167652f776562702c2a2f2a3b713d302e380d0a41636365" \
                                    "70742d4c616e67756167653a20656e2d55532c656e3b713d302e350d0a416363" \
                                    "6570742d456e636f64696e673a20677a69702c206465666c6174652c2062720d" \
                                    "0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a55706772616465" \
                                    "2d496e7365637572652d52657175657374733a20310d0a5365632d4665746368" \
                                    "2d446573743a20646f63756d656e740d0a5365632d46657463682d4d6f64653a" \
                                    "206e617669676174650d0a5365632d46657463682d536974653a206e6f6e650d" \
                                    "0a5365632d46657463682d557365723a203f310d0a0d0a485454502f312e3020" \
                                    "323030206f6b0d0a436f6e74656e742d747970653a20746578742f68746d6c0d" \
                                    "0a0d0a3c48544d4c3e3c424f4459204247434f4c4f523d222366666666666622" \
                                    "3e0a3c7072653e0a0a735f736572766572202d6e6f5f636f6d70202d63657274" \
                                    "2073736c5f736372697074732f4d79526f6f7443412e70656d202d746c73315f" \
                                    "32202d636970686572204145533235362d534841202d6b65792073736c5f7363" \
                                    "72697074732f4d79526f6f7443412e6b6579202d61636365707420343433202d" \
                                    "6465627567202d777777202d6b65796c6f6766696c65202f686f6d652f617865" \
                                    "6c2f6165733235365f7368612e6b6579200a5365637572652052656e65676f74" \
                                    "696174696f6e20495320737570706f727465640a436970686572732073757070" \
                                    "6f7274656420696e20735f7365727665722062696e6172790a544c5376312e33" \
                                    "202020203a544c535f4145535f3235365f47434d5f5348413338342020202054" \
                                    "4c5376312e33202020203a544c535f43484143484132305f504f4c5931333035" \
                                    "5f534841323536200a544c5376312e33202020203a544c535f4145535f313238" \
                                    "5f47434d5f5348413235362020202053534c76332020202020203a4145533235" \
                                    "362d534841202020202020202020202020202020200a2d2d2d0a436970686572" \
                                    "7320636f6d6d6f6e206265747765656e20626f74682053534c20656e6420706f" \
                                    "696e74733a0a544c535f4145535f3132385f47434d5f53484132353620202020" \
                                    "20544c535f43484143484132305f504f4c59313330355f53484132353620544c" \
                                    "535f4145535f3235365f47434d5f534841333834202020200a4145533235362d" \
                                    "5348410a5369676e617475726520416c676f726974686d733a2045434453412b" \
                                    "5348413235363a45434453412b5348413338343a45434453412b534841353132" \
                                    "3a5253412d5053532b5348413235363a5253412d5053532b5348413338343a52" \
                                    "53412d5053532b5348413531323a5253412b5348413235363a5253412b534841" \
                                    "3338343a5253412b5348413531323a45434453412b534841313a5253412b5348" \
                                    "41310a536861726564205369676e617475726520416c676f726974686d733a20" \
                                    "45434453412b5348413235363a45434453412b5348413338343a45434453412b" \
                                    "5348413531323a5253412d5053532b5348413235363a5253412d5053532b5348" \
                                    "413338343a5253412d5053532b5348413531323a5253412b5348413235363a52" \
                                    "53412b5348413338343a5253412b5348413531320a537570706f727465642067" \
                                    "726f7570733a207832353531393a7365637032353672313a7365637033383472" \
                                    "313a7365637035323172313a6666646865323034383a6666646865333037320a" \
                                    "5368617265642067726f7570733a207832353531393a7365637032353672313a" \
                                    "7365637033383472313a7365637035323172313a6666646865323034383a6666" \
                                    "646865333037320a2d2d2d0a4e65772c2053534c76332c204369706865722069" \
                                    "73204145533235362d5348410a53534c2d53657373696f6e3a0a202020205072" \
                                    "6f746f636f6c20203a20544c5376312e320a2020202043697068657220202020" \
                                    "3a204145533235362d5348410a2020202053657373696f6e2d49443a200a2020" \
                                    "202053657373696f6e2d49442d6374783a2030313030303030300a202020204d" \
                                    "61737465722d4b65793a20413332364530373034383644353646444444384131" \
                                    "4343393131464236393236463044354333423439333442314641353837303930" \
                                    "3446313133433946423036363745424544433638373539373631364235303545" \
                                    "37323833413736363634410a2020202050534b206964656e746974793a204e6f" \
                                    "6e650a2020202050534b206964656e746974792068696e743a204e6f6e650a20" \
                                    "20202053525020757365726e616d653a204e6f6e650a20202020537461727420" \
                                    "54696d653a20313637303834313131340a2020202054696d656f75742020203a" \
                                    "20373230302028736563290a202020205665726966792072657475726e20636f" \
                                    "64653a203020286f6b290a20202020457874656e646564206d61737465722073" \
                                    "65637265743a207965730a2d2d2d0a20202030206974656d7320696e20746865" \
                                    "2073657373696f6e2063616368650a2020203020636c69656e7420636f6e6e65" \
                                    "637473202853534c5f636f6e6e6563742829290a2020203020636c69656e7420" \
                                    "72656e65676f746961746573202853534c5f636f6e6e6563742829290a202020" \
                                    "3020636c69656e7420636f6e6e6563747320746861742066696e69736865640a" \
                                    "20202031207365727665722061636365707473202853534c5f61636365707428" \
                                    "29290a20202030207365727665722072656e65676f746961746573202853534c" \
                                    "5f6163636570742829290a202020312073657276657220616363657074732074" \
                                    "6861742066696e69736865640a202020302073657373696f6e20636163686520" \
                                    "686974730a202020312073657373696f6e206361636865206d69737365730a20" \
                                    "2020302073657373696f6e2063616368652074696d656f7574730a2020203020" \
                                    "63616c6c6261636b20636163686520686974730a202020302063616368652066" \
                                    "756c6c206f766572666c6f7773202831323820616c6c6f776564290a2d2d2d0a" \
                                    "6e6f20636c69656e7420636572746966696361746520617661696c61626c650a" \
                                    "3c2f7072653e3c2f424f44593e3c2f48544d4c3e0d0a0d0a"
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "41251c5e55e74c0c2f9fdd2480619ed1812b6417243364cc0990225c93e2fb62" \
                                    "6d51ba90f00671a2bbf03a3604668d6601b18d25bdd719bccfda3ac540e4cd87" \
                                    "5ee6da20044dc4142f71e8639ff69fa6a7b98e4e6e5cfe0762428fdccc3d2658" \
                                    "15ca1d66e084f22ecc6e545bcdd162cb4a8c7ec920ffb180c087dbdf33cfc3fa" \
                                    "b40493c5fade697b677aa9b3f0998fc95352425ef0ac8c13a774697d019756fc" \
                                    "91a226a6eaaa50503a5fa1909168d828eadafd891a4469d66b7cb536c50b6952" \
                                    "9fb8b9060daf7c4456b25aa7555e1742eb40fdbd779f88c20e9f6dafe60620fe" \
                                    "574c37232b5fb2b2f99cfb1bc40ea1d2ee75f1dd1acf7e81cd009b8a310c49ed" \
                                    "5037a7a81f7d3488941824cfedc029059c595e62dfcd44a72753b655bda77ad4" \
                                    "6a9b642c4b204355160f53ed5c37339f5d689ee5cac3bc01d5946d9bbcfb3aca" \
                                    "73448192f6d6305a1235ed2aac0e59439a85eb12721a09e4515f995217741a4f" \
                                    "673e4d62e6a1ad9e9a37e89c821963efb3158e851cd2f15934738763263718b0" \
                                    "d974e26c8de69d24c49846373a542a847124e8b92fa9c1495d07e57aa612347c" \
                                    "aa0958c3b2d784a329c2a6771575ca87fd732e989f14a0753065a3fe39ee22f4" \
                                    "cee0836123bd11f5fb85c4d6659cc2935c9d4fde25ab583eb5a88c08a2851581" \
                                    "722a44e4316371ef2928a71eceefa7b4a96e7fe7a841e78b2bcdf2251b80d17a" \
                                    "2e65c2bfc5c9469f1e2af03b21ff2310abf1183f3f8f8688e9a831be6c356aec" \
                                    "e682be1263592cf9a8458836822596df1c5cc5b7c1ad2acc752167e0db2c770f" \
                                    "2232c1e2d1f7082a5553d3da316d393546d67a17aea378c55ac261e75e146bfb" \
                                    "d3b67526736dd1baa295cc99b34c96366faecace235d6fb0f421c358c4447623" \
                                    "62b249d5f0f7db3e8d401343bd53d8777f110f77d7bf4bf7f9b35c9ff1bdab09" \
                                    "c3536389062d814420fb32abc7dc353a73b98e4d855551ebe268e704a7b0b7eb" \
                                    "c0700777b6ff2e2a5865cd5f563ac6575109ca052f2d2644b9ec558fd8d04b42" \
                                    "419e5456d410f912bf5463264ae519892a116f0764e79e3324ea37401e605e7c" \
                                    "0008f2f7055f38ce469a1719bc92878649e11720fcde3033504727bd957bbb1c" \
                                    "6d84792dae7754c4fce9a4618ae225715dd2d2c85260a79e1760fd7ed88ae670" \
                                    "ec0508dc8ce1bcb5556f9b5ea85cc82541798a7cdd11e48cbd922ff45c821a68" \
                                    "21e7d0ce8ed18588b313cb41bd39a97cac29c00ddfbf3ee6b5511a1c9e499662" \
                                    "4c625bd88e1786a6ee3d7de54500947cc8c4de49ef0379c4404604a8743a4444" \
                                    "adafce52c0ae9c6971c21609bd991facba1b36b50f56f123aabcce6fb3f10283" \
                                    "7edc4e1d164cff7dd2caf9728270b3e5821d23eeb568a66b70f8915a3235528e" \
                                    "467a8419562cbb6eb7bd33e1d3723e89458c855186d384a91792de5b1cfc7e5e" \
                                    "48efb07ae287b027555b78f1f28cd548e399d6eeda43299bd699b0b67ee90c72" \
                                    "cbda149524f78cdff2459ba862cab83c3546ff9fa2b7656c770440d9b113695d" \
                                    "ee206f3f33d6f6f13024a9cd4554f19ee5a751bd566447e9b85a055c1f826367" \
                                    "fd5f1dd1f3389f31f51f47d423627a70357478d4c535ee1c00bce65f84624033" \
                                    "8f5bc9885e1a99614eb75bfb39dfb5b0c371a2e4259155cbf126ab84ab500510" \
                                    "7d88d644bbd4b4c3ebce46f5915ca05396b63394244f8663b956f25f116e32ef" \
                                    "39c2e343db4ea0b86079a8bdf4dd022e5d3cd386b7d39543bbbb658a470b4b2c" \
                                    "f3e5ce40905b2d6857f609fec580048d5b0528f7a540e3632f94a2cc4ae5f6cf" \
                                    "1818b36dfb908762035bd7e6161c87fda4c4a51520436fd9a16ecb174e20ae8f" \
                                    "5cce2201d9f83677cae2cf92df6ed5e7507004bb60742d10c3c02cf81fb5ced1" \
                                    "51005c2a41c5317a8d211baf130bfb19ad4e4fa9893a18c4295f3631ce2382b8" \
                                    "4d8e4c0d1c9d29271f2a0633b16138ebd9c1579a6926d8eb3b0b5f29a7417219" \
                                    "5cc1ee4702e3a1390e20834c2375abde1c026a3ac2072b6347dd600391aae8fb" \
                                    "361d4aaefbbba7c8674c59021c93efefecd462d3a85fe3dee6cdb6f92a3ebdc9" \
                                    "8c320c7492782ac4bff107fc18c32a49f3734f6b75e332485fdc4cc9987c1e9c" \
                                    "ff7809092a13567f0ce87b51f28241fa81803e95829a030be1d9a235bcec1fe6" \
                                    "035a586cd73b9393d5b25fdbbc4d8bbc15615da6a18264de4511356f253bf551" \
                                    "f25dfb62e481956142e4608c42a3108966d326c330af82f1eaaeb62d8ff946d8" \
                                    "ae6814e1530f19f27b1d675585cab823c1ffda5b3d3f81b18237e714018314a1" \
                                    "a5aaba914abc2387be070e8dce4c8cc3a6ebac4bea48f28742838660e77dd6fd" \
                                    "1e4652cadcf0ec174fdd768af6706fae42eae66ad8ffcdefec7b83d006ad5fef" \
                                    "ac9e645a382320e06f7e8d9ad712835aa767feb59f430981f7244e49f1c818b3" \
                                    "e3ab6973a4aa2aa4aa21ee514a24045f41ee813b343165cf7583f4f6e52f94b2" \
                                    "26a3193301d351a27ee8fec6b57d5eb174098f5d3ab4a101612b3f1be8a60169" \
                                    "1933baabe3243174f924534d3a67eca1f4179af30c23968afb7e887a66322c27" \
                                    "383bc8160fa9d597a5233ad015066462daaabde0e742af83a995d019a3044f3c" \
                                    "2413e8708753b3c6b7000e8b8a9dcc4a14c55f73fc5cf1f29e8e4738391b5186" \
                                    "c6dbc79f3668bc024c5bda3e824b104ff57c46c28c8d3f10cd3ef8504005b49f" \
                                    "c1cc62053407eff5bae88463bc36f0ced08b4f6e2a70c1f7be9f369dac1f247b" \
                                    "86b590cfcebe20e6d97ea76a49c5b3f37ca05fd87e17382f7a6eb7fabf7b0633" \
                                    "6ad732f11a0ba2ee7ad4591c23b1d192b413a4fa5b7f518e286037d32f99338f" \
                                    "608aefeda468cde90b3b593d90feb1e0d8296bb8be5c9a61ef574a1359c7b999" \
                                    "2be79a753609b484d5e195b70e1a10681f61df7de7b9ddf8dcc7671af3765995" \
                                    "1f16fec4ab91c530d8ae9940648a71b29df49f3870310dd9a6b59562def57c37" \
                                    "64823f2052b7d1888b2824211e9a6a73edbad5fd5802c40e382163cfd72a62a2" \
                                    "bcd653375d5f7af80ee237a29605caf017ca80642c2886d0dbb8d407d338cfff" \
                                    "b78e07238e51c67aca747466d15682929535738c170630e4387da85616cce70a" \
                                    "2cab5169050aea42d093bdcd1a61306ec426ccd2e7bdfe15bd72a53f46b49bf8" \
                                    "2e2c49d4a4c28a4b1154db52412ae9f717bd8c675d99cdf85ad5b2d4064f28c2" \
                                    "161ab6cb43504ab71105ca643c28a7e9ba9099fcb938ceaed4fbf2b36dd0ea8f" \
                                    "25621a0def5b77790ce6d4c18e749a69003fe632be90cd21ea7400e4782c8a53" \
                                    "ef1c27f69526d3d76f3c5c0d9bfdfe1d1c5d480f08f8f8b5a00b826d4de3ecd8" \
                                    "5fc7fb16cf10afc963c91a42802ff99f975df08d866d9f516048fca10af41425" \
                                    "c721f8a6e341f784cb5d9d5efb2026d725ed25d83ca4ecf64b3d6735797e63f0" \
                                    "bf05a65d592d42158d0b970478ba8f1132c21a8736160d68c994ab298c29d0eb" \
                                    "6142dfd44adc5ebae8be97452700b2120fe7145e8af5d8ef292963d8ebe708d7" \
                                    "5de9e720b777997b1c81abc351c7266f"
    return content_tls_appdata_all_cipher