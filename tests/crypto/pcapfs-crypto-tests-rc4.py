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

class TestRc4:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes128-cbc.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2758_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2758_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes128-cbc.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2758_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2758_SSL'), 'rb') as f:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes128-cbc.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/0-117', 'ssl/0-2758_SSL', 'tcp/0-4_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('http/0-117')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('ssl/0-2758_SSL')
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = "474554202f20485454502f312e310d0a486f73743a203132372e302e302e" \
                                    "310d0a557365722d4167656e743a206375726c2f372e37362e310d0a4163" \
                                    "636570743a202a2f2a0d0a0d0a" \
                                    "" \
                                    "485454502f312e3020323030206f6b0d0a436f6e74656e742d747970653a" \
                                    "20746578742f68746d6c0d0a0d0a3c48544d4c3e3c424f4459204247434f" \
                                    "4c4f523d2223666666666666223e0a3c7072653e0a0a735f736572766572" \
                                    "202d6b6579206b65792e70656d202d6365727420636572742e70656d202d" \
                                    "777777202d636970686572204145533132382d534841202d706f72742034" \
                                    "3433202d6e6f5f746c73315f33200a5365637572652052656e65676f7469" \
                                    "6174696f6e20495320737570706f727465640a4369706865727320737570" \
                                    "706f7274656420696e20735f7365727665722062696e6172790a544c5376" \
                                    "312e33202020203a544c535f4145535f3235365f47434d5f534841333834" \
                                    "20202020544c5376312e33202020203a544c535f43484143484132305f50" \
                                    "4f4c59313330355f534841323536200a544c5376312e33202020203a544c" \
                                    "535f4145535f3132385f47434d5f5348413235362020202053534c763320" \
                                    "20202020203a4145533132382d5348412020202020202020202020202020" \
                                    "20200a2d2d2d0a4369706865727320636f6d6d6f6e206265747765656e20" \
                                    "626f74682053534c20656e6420706f696e74733a0a544c535f4145535f32" \
                                    "35365f47434d5f5348413338342020202020544c535f4348414348413230" \
                                    "5f504f4c59313330355f53484132353620544c535f4145535f3132385f47" \
                                    "434d5f534841323536202020200a4145533132382d5348410a5369676e61" \
                                    "7475726520416c676f726974686d733a2045434453412b5348413235363a" \
                                    "45434453412b5348413338343a45434453412b5348413531323a45643235" \
                                    "3531393a45643434383a5253412d5053532b5348413235363a5253412d50" \
                                    "53532b5348413338343a5253412d5053532b5348413531323a5253412d50" \
                                    "53532b5348413235363a5253412d5053532b5348413338343a5253412d50" \
                                    "53532b5348413531323a5253412b5348413235363a5253412b5348413338" \
                                    "343a5253412b5348413531323a45434453412b5348413232343a45434453" \
                                    "412b534841313a5253412b5348413232343a5253412b534841313a445341" \
                                    "2b5348413232343a4453412b534841313a4453412b5348413235363a4453" \
                                    "412b5348413338343a4453412b5348413531320a53686172656420536967" \
                                    "6e617475726520416c676f726974686d733a2045434453412b5348413235" \
                                    "363a45434453412b5348413338343a45434453412b5348413531323a4564" \
                                    "32353531393a45643434383a5253412d5053532b5348413235363a525341" \
                                    "2d5053532b5348413338343a5253412d5053532b5348413531323a525341" \
                                    "2d5053532b5348413235363a5253412d5053532b5348413338343a525341" \
                                    "2d5053532b5348413531323a5253412b5348413235363a5253412b534841" \
                                    "3338343a5253412b5348413531323a45434453412b5348413232343a4543" \
                                    "4453412b534841313a5253412b5348413232343a5253412b534841313a44" \
                                    "53412b5348413232343a4453412b534841313a4453412b5348413235363a" \
                                    "4453412b5348413338343a4453412b5348413531320a537570706f727465" \
                                    "6420456c6c69707469632047726f7570733a205832353531393a502d3235" \
                                    "363a583434383a502d3532313a502d3338340a53686172656420456c6c69" \
                                    "707469632067726f7570733a205832353531393a502d3235363a58343438" \
                                    "3a502d3532313a502d3338340a2d2d2d0a4e65772c2053534c76332c2043" \
                                    "6970686572206973204145533132382d5348410a53534c2d53657373696f" \
                                    "6e3a0a2020202050726f746f636f6c20203a20544c5376312e320a202020" \
                                    "20436970686572202020203a204145533132382d5348410a202020205365" \
                                    "7373696f6e2d49443a203639303538393631453033314635393539423341" \
                                    "384534434545384238313835343443434430354238313130444144304636" \
                                    "31383533423441453132323937450a2020202053657373696f6e2d49442d" \
                                    "6374783a2030313030303030300a202020204d61737465722d4b65793a20" \
                                    "453241323432423737363245354236453631383946363639343043443642" \
                                    "383735323235313832333934433942343835313934313837383639454236" \
                                    "323843464539413135453336323333373043443045324537314337413345" \
                                    "3432463738390a2020202050534b206964656e746974793a204e6f6e650a" \
                                    "2020202050534b206964656e746974792068696e743a204e6f6e650a2020" \
                                    "202053525020757365726e616d653a204e6f6e650a202020205374617274" \
                                    "2054696d653a20313632313534323733330a2020202054696d656f757420" \
                                    "20203a20373230302028736563290a202020205665726966792072657475" \
                                    "726e20636f64653a203020286f6b290a20202020457874656e646564206d" \
                                    "6173746572207365637265743a207965730a2d2d2d0a2020203120697465" \
                                    "6d7320696e207468652073657373696f6e2063616368650a202020302063" \
                                    "6c69656e7420636f6e6e65637473202853534c5f636f6e6e656374282929" \
                                    "0a2020203020636c69656e742072656e65676f746961746573202853534c" \
                                    "5f636f6e6e6563742829290a2020203020636c69656e7420636f6e6e6563" \
                                    "747320746861742066696e69736865640a20202031207365727665722061" \
                                    "636365707473202853534c5f6163636570742829290a2020203020736572" \
                                    "7665722072656e65676f746961746573202853534c5f6163636570742829" \
                                    "290a2020203120736572766572206163636570747320746861742066696e" \
                                    "69736865640a202020302073657373696f6e20636163686520686974730a" \
                                    "202020312073657373696f6e206361636865206d69737365730a20202030" \
                                    "2073657373696f6e2063616368652074696d656f7574730a202020302063" \
                                    "616c6c6261636b20636163686520686974730a2020203020636163686520" \
                                    "66756c6c206f766572666c6f7773202831323820616c6c6f776564290a2d" \
                                    "2d2d0a6e6f20636c69656e7420636572746966696361746520617661696c" \
                                    "61626c650a3c2f7072653e3c2f424f44593e3c2f48544d4c3e0d0a0d0a"
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "01751796f6af6dbbdff6d31362744e1dad838554d35f1261cdc19641675f" \
                                     "9e7881c55aa7aadcaf592458a3287b2f142765bc426c56a21cb7612aa45a" \
                                     "7fab5ffc65e133942d1b9269c43abc21c22a6414dbb4519d553b7328f1ed" \
                                     "e4484aa0385b96abda04b59258a44451af7e79c3a54a9399e02e" \
                                     "" \
                                     "44b77f1bde6947b169e76648f694700571f53b53348132ff41779fb45e8" \
                                     "510a52598c7c9e10d2cf793a5e498d55667521597af0c170bff5a005bb3" \
                                     "c7d04b8b4defff7de17b705bcd3524411a1a4e8c67b202526a98f8ff782" \
                                     "873f871b89c035842d0a87f6f1e308710ae584b4beb4c306b56cc9cca20" \
                                     "509f26d54aece1b629148bead45ba1d1a888b6efedc1930622ecd6e29bb" \
                                     "26cc660a710359cf7cb86ff7266c637b4861db56fb467c5d99dfcd037c2" \
                                     "bcf951f75d49267e4575c10a3737b5fe4f3e0a87249bdca8b925257a60b" \
                                     "b432299d28348d69f1b2500ceb6698a704d08e11c4427eafe4dd00da759" \
                                     "06d2f3c1ecabd30e88fa0685a1af3ba5fb7f9c0e630b328fff8e7c2c81f" \
                                     "a8544808e721c2b0098db0716ba81c3737d3d162d68f741e5f3cb09a6b5" \
                                     "287a305368388039aa313f1f121c901a49e3f3a69e01095e70b46f65702" \
                                     "1c143432ba271cac5b1e37f6cf7cbc9578f32c7dda71cb4f5d76531c7e7" \
                                     "db390af7405c29289bea6e277792902084ce2b3e25eeb39b3250e9ba825" \
                                     "f8a2e2eb8b5ca4405f3d266e3a7450319a82cfae669bda1a4c9ffa6c60f" \
                                     "328ccf5345b4385c88af8994eae95982342bdc3a276e939f17dd38ff9c9" \
                                     "0e37484b4dd41aa73c7826987ade34c3db2dbb295ac11687e60d4db5e52" \
                                     "a687dceff86a903ba570eb6107a40c57f72813f248ffc9756b94821fc2b" \
                                     "2a2388adc8f7dbf3454589d6c27b322d7125440290d8b024a599c3f8c24" \
                                     "7b5d98bd986fcba65f97c8196b82c87512a29606d3b578a3376e6f75ba1" \
                                     "7baa19a20fa052b77ebcee394468e7fb6006a713690aed0d52cb87870c1" \
                                     "befaea7387ff5610e6af94c51a6578d61010672172208cc610d7792f2c3" \
                                     "59ff86e32e1796d3bd4b77259595db803b1fc4fdadcec87d84348ab29e3" \
                                     "bbc5d1351458af8ada8cc2038c5913bc2d209486e427414663bb8aab2e4" \
                                     "82172736c90f07ae119ce7dec7f1fce073f1dac38e1110849610ecbcabc" \
                                     "ffb6d5d047d27908660263b5bd8c5afd74fd44f1f5bb9751fc342e00c6c" \
                                     "40bb26de5b6f0acbb052db0668176ad2115584cd31b7c76434a472fea96" \
                                     "a1cb03f4093da5ac4d4b638efdfd50e5fcb54a33be53e2e984e98db6278" \
                                     "0695077a9999c69c13dd68900ce94b098572f0f460500dc32f2e3c8cd4e" \
                                     "250f88ac0c46eb49a0becea21ae492caa12cb14e7c638777e33b50935f6" \
                                     "31951123f06b29b9ac7936f13aa0db8eb6353cb22d8334156108a836331" \
                                     "948ef265c6452c39e23cb960df400e2316fe8215206762455844ec81920" \
                                     "2fa4863aa822cf11977de96d260d18121d072425a13cee14a401a128440" \
                                     "fbd51db5198e5f12ece3ec8a2ae563ce85397e126e1337e147f7499ae28" \
                                     "98575b0186ac4be024ac0d9ef41bc30a162c70c54a7ae8d64819cddbe95" \
                                     "c047952919f91bd9ccb9e9fca710cc4e5229dcefa180f21f866c955f9a5" \
                                     "01232b80e11e1049e08d9cfabd9a98fae5996bcec809cfda2c57efc42df" \
                                     "53ee6dcf219c25cf1fe74a50468810eac113e04d3b82c4421b2d19238d0" \
                                     "c0b2fe86ea649f92f6e6ce85bac29e1c850232af95e52858efa7e68542e" \
                                     "7f57978097ffe4ccb3addafc7bfe16d0a50abd493ff111e4659cb573c0d" \
                                     "0592521cb34f0632a00edce3489081c213299afe2e25dc6ebad0feb8598" \
                                     "d45f77abcdfa8b54226a44d824b083516fa4eee3c2411911621cdb47ba3" \
                                     "ce83827404fce80cebf92ad51fd56ab7be92c75f1cb7fd8eec7f82b0ae4" \
                                     "1447cb58bd6ffd07368feddf2073917a6323c1cbd97693e764747c0955d" \
                                     "d8f6932837a1e4f4514bf6c2953cdac5fb76ff87e8507a642e3e9c2837f" \
                                     "18a32b9c4c802335603e61f03872eaaf35b5ad9270cbe9d2183a7c220d1" \
                                     "9ad85ce731cc0bdcc3b3f2e06f53c6471f27a7ffa18be17ecbe6ffdb0c3" \
                                     "1d484e4bbcd17ace4162d1981a0e1c989dae9bfda1a4d52eca20ce4a986" \
                                     "64384cd44cbc62bcf67d0b5475ab70076b350328e43bbe21385b4928e32" \
                                     "3e40bc103d6af3190a6388ea59aaf54a938e54f1397faac188a198fdfab" \
                                     "35806a605027f8e4fa9bb45cf9353450fbe3dc922ecf1a4ee7e43a45a56" \
                                     "10533b1757094d9bf5c7119f3a4f341c1a1a7b2484331a0aa764f760ff8" \
                                     "20ad2e4d8479a464dc2f7530246bc8d343b1f294fd14846d9cae56c724e" \
                                     "2c475f4a391f247a8c0bd74c868693cec5f6b5ba92585e4d0586971f930" \
                                     "62262bce884952b2666f8b0094df5872c168f86926d25939feb3659a486" \
                                     "215f33c61077fbffc5120f5625bb3132121b17ba2f68731b152e60fe1e6" \
                                     "d7aa425cdf3acf1a036640a9dd1afbdf2f972d2bc8a6ab2c05c887638cb" \
                                     "16b9f5d571dae7538b7a6e85d02c14b1bd78606694160edb3e8f16a853d" \
                                     "95ee52ffce9dd6d81cccf2c1980ca31da2fbf6bebf60a233dca5fab602f" \
                                     "9c3960a41234b32fb45059d5746a2c6e03ccf4c4c103d82ebf73bc428f0" \
                                     "69755e67032054ed848f379e336a8b6a4e32cfd0477d34a90248a5adc7c" \
                                     "08c0fc614918c1117d4a3d1877307797143b334ae99d0d0954e7ea49dae" \
                                     "a2f5d82395c47a8664b726283956fd4f2004ba9cdb9b9e2ef8025575b91" \
                                     "526e92ca82655c26f63014f834bb1897583024bfbc95487e29a08e91b77" \
                                     "88ddad3a237bfe88c3bdfd986f0a170a218bc68dcc1b1b7348ff7a19a01" \
                                     "7d9249768176c05e3e8db1c686c5736e07c9c3d8ac713712742ead111f7" \
                                     "75a57d54a750bb6ccaa83bcc3f676fbb1d51c545251de1ffde64c8066bb" \
                                     "dc81fc9f40f5475f73b989911de34cbe4ed532e1b4a811dd67bba8f220a" \
                                     "e5b245066ccdbd2a0dc843e92e52cb436d436379e0486a6af3e1d3e239d" \
                                     "2b83657668ff505b176e6001a28bb9e849ec5c9a4d5d3c075ec08b3d343" \
                                     "8137236b2e0d4ed79750e80ef05887e1ace700b6b07a87650dba82664c2" \
                                     "f42289d1ffeee851ac3430ed09582e33dc01c60e31edb63e02bbb27eb3d" \
                                     "95b42108e9f4792ab742078916e2a5625d55ce113091d7c13290dbf5d64" \
                                     "932fffc7b050d93d5cedc5a6964a2e71d70bb85d06e4e433727e35ba3b3" \
                                     "909195150c16a72c7450c098845726539b1605ec83f29884bc826fad4f2" \
                                     "b878536c2844017db359ce4fd26a8627c52c715c565b39295e758537fb4" \
                                     "57f3daf3b0f181a47777d24ab719684a63f39612ef56cb71a27a3e13dc5" \
                                     "dfea23aed355fb86891211dc26c1e6c1e95f"
    return content_tls_appdata_all_cipher
