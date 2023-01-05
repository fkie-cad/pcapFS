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

class TestAes128GcmSha256:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes128-gcm-sha256.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2078_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2078_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes128-gcm-sha256.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2078_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2078_SSL'), 'rb') as f:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes128-gcm-sha256.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/0-483', 'ssl/0-2078_SSL', 'tcp/0-4_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('http/0-483')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('ssl/0-2078_SSL')
    return sorted(expected_files)


@pytest.fixture
def content_tls_appdata_all_plain():
    content_tls_appdata_all_plain = "474554202f20485454502f312e310d0a486f73743a206c6f63616c686f73740d" \
                                    "0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b2055" \
                                    "62756e74753b204c696e7578207838365f36343b2072763a3130382e30292047" \
                                    "65636b6f2f32303130303130312046697265666f782f3130382e300d0a416363" \
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
                                    "32202d636970686572204145533132382d47434d2d534841323536202d6b6579" \
                                    "2073736c5f736372697074732f4d79526f6f7443412e6b6579202d6163636570" \
                                    "7420343433202d6465627567202d777777202d6b65796c6f6766696c65202f68" \
                                    "6f6d652f6178656c2f617364662e6b6579200a5365637572652052656e65676f" \
                                    "74696174696f6e20495320737570706f727465640a4369706865727320737570" \
                                    "706f7274656420696e20735f7365727665722062696e6172790a544c5376312e" \
                                    "33202020203a544c535f4145535f3235365f47434d5f53484133383420202020" \
                                    "544c5376312e33202020203a544c535f43484143484132305f504f4c59313330" \
                                    "355f534841323536200a544c5376312e33202020203a544c535f4145535f3132" \
                                    "385f47434d5f53484132353620202020544c5376312e32202020203a41455331" \
                                    "32382d47434d2d5348413235362020202020202020200a2d2d2d0a4369706865" \
                                    "727320636f6d6d6f6e206265747765656e20626f74682053534c20656e642070" \
                                    "6f696e74733a0a544c535f4145535f3132385f47434d5f534841323536202020" \
                                    "2020544c535f43484143484132305f504f4c59313330355f5348413235362054" \
                                    "4c535f4145535f3235365f47434d5f534841333834202020200a414553313238" \
                                    "2d47434d2d5348413235360a5369676e617475726520416c676f726974686d73" \
                                    "3a2045434453412b5348413235363a45434453412b5348413338343a45434453" \
                                    "412b5348413531323a5253412d5053532b5348413235363a5253412d5053532b" \
                                    "5348413338343a5253412d5053532b5348413531323a5253412b534841323536" \
                                    "3a5253412b5348413338343a5253412b5348413531323a45434453412b534841" \
                                    "313a5253412b534841310a536861726564205369676e617475726520416c676f" \
                                    "726974686d733a2045434453412b5348413235363a45434453412b5348413338" \
                                    "343a45434453412b5348413531323a5253412d5053532b5348413235363a5253" \
                                    "412d5053532b5348413338343a5253412d5053532b5348413531323a5253412b" \
                                    "5348413235363a5253412b5348413338343a5253412b5348413531320a537570" \
                                    "706f727465642067726f7570733a207832353531393a7365637032353672313a" \
                                    "7365637033383472313a7365637035323172313a6666646865323034383a6666" \
                                    "646865333037320a5368617265642067726f7570733a207832353531393a7365" \
                                    "637032353672313a7365637033383472313a7365637035323172313a66666468" \
                                    "65323034383a6666646865333037320a2d2d2d0a4e65772c20544c5376312e32" \
                                    "2c20436970686572206973204145533132382d47434d2d5348413235360a5353" \
                                    "4c2d53657373696f6e3a0a2020202050726f746f636f6c20203a20544c537631" \
                                    "2e320a20202020436970686572202020203a204145533132382d47434d2d5348" \
                                    "413235360a2020202053657373696f6e2d49443a200a2020202053657373696f" \
                                    "6e2d49442d6374783a2030313030303030300a202020204d61737465722d4b65" \
                                    "793a203730383044353345393533453133354644433441353542413943323936" \
                                    "4141333531304234444538333032334139414136354238433030393130394438" \
                                    "3137384142363334394230343331363139333137444139384642343342444138" \
                                    "3833450a2020202050534b206964656e746974793a204e6f6e650a2020202050" \
                                    "534b206964656e746974792068696e743a204e6f6e650a202020205352502075" \
                                    "7365726e616d653a204e6f6e650a2020202053746172742054696d653a203136" \
                                    "37323232323839340a2020202054696d656f75742020203a2037323030202873" \
                                    "6563290a202020205665726966792072657475726e20636f64653a203020286f" \
                                    "6b290a20202020457874656e646564206d6173746572207365637265743a2079" \
                                    "65730a2d2d2d0a20202030206974656d7320696e207468652073657373696f6e" \
                                    "2063616368650a2020203020636c69656e7420636f6e6e65637473202853534c" \
                                    "5f636f6e6e6563742829290a2020203020636c69656e742072656e65676f7469" \
                                    "61746573202853534c5f636f6e6e6563742829290a2020203020636c69656e74" \
                                    "20636f6e6e6563747320746861742066696e69736865640a2020203120736572" \
                                    "7665722061636365707473202853534c5f6163636570742829290a2020203020" \
                                    "7365727665722072656e65676f746961746573202853534c5f61636365707428" \
                                    "29290a2020203120736572766572206163636570747320746861742066696e69" \
                                    "736865640a202020302073657373696f6e20636163686520686974730a202020" \
                                    "302073657373696f6e206361636865206d69737365730a202020302073657373" \
                                    "696f6e2063616368652074696d656f7574730a202020302063616c6c6261636b" \
                                    "20636163686520686974730a202020302063616368652066756c6c206f766572" \
                                    "666c6f7773202831323820616c6c6f776564290a2d2d2d0a6e6f20636c69656e" \
                                    "7420636572746966696361746520617661696c61626c650a3c2f7072653e3c2f" \
                                    "424f44593e3c2f48544d4c3e0d0a0d0a"
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "0000000000000001b1a4425fb2c26f24aede34667e36e76559257f8ba56a633d" \
                                    "54c8fa107dc11a064de86378474dbc56e3d264cc3bf015d91800f80e330b0101" \
                                    "f3cb7a97f628adbd79f8afbca905de9068d877593fba33c28bd92aeefdb04e61" \
                                    "31f8e8296e81b0409cbd7a0b8a51f8caf9db21fa1b19dad37a9f74b41b3d2c3b" \
                                    "133169b9177e3bfe8815047823a682aa866004ec1a24cbcc4590eda81906e765" \
                                    "949122e5f51fda0e2ac4e88432277e1edb4d7655579634099275b4c9b3c7d808" \
                                    "b90272bb9abec429f86c683f85d6f47ecd5cbe9dc209042c5c0a7ecb6685716d" \
                                    "63aa0a779c067f415ac483c65f9317c26974754589934b1c858727f370fbfde9" \
                                    "8c1996825524d253c28ae67fb562494d9313fca659ccdac148766c9156f37e99" \
                                    "07b1f6dd008f9a6457d05394bbab858b13b285798baa44b9baec08e92bb42369" \
                                    "97c332bc6d5adb298f705810096c4e0416dafb515ec955540d04a4410518557d" \
                                    "1cfc53894793cef8ec2fc9dec709c755a9b52a402aa45b570072789fddc7a844" \
                                    "b1252f51910b626bd589920b2a2665e621753ac7ed301124b4d6aed30ea0ac53" \
                                    "e933825b6e05f0e6ba268d2462f6f483925fe18a88c6589fe056687ec48da8c7" \
                                    "f34bf294dda7daa0c8efb7833f0ef78af79cc5445aaae995b8f61d827185384d" \
                                    "7c8eee94d97d8a588082c95052071cdb890a0022cbc1313757fc9f21b5db5929" \
                                    "e631d1fbcb4bca8394b6d64e09885e5a18d55f856a8be6d87b2401081035ec5f" \
                                    "ac7813b190601d2ad7d223dfc8ea4fcb1325e8fab0c39981c08602647ddd7071" \
                                    "72fdcc625f3d955d1c159da593f335f1a21a49a8a693d9caa3c00e32b3414be8" \
                                    "5d5d556e4ddae6eaf3d49a38828af7c095e6d0efd693205dbfc5fd260ea8bc38" \
                                    "022128c392c6710ae682ec3b2c38540aa4290b2e6cca157577408b1551c60ddf" \
                                    "fad8be3611a0b054141ed07a9382d4e9796c3429d7a249781fbd0a67a05c17c1" \
                                    "ce1377a413ccf89ff176a951a7cb51560bf166fc56915f81a25b5459a982b4e1" \
                                    "ea3c6c0b4a3e83c61b1b33fa65538cf6f4e2e5756c7a0106c3291bc93fb4920b" \
                                    "2ea2fd3acf7939d4679295cdac4e318c541a1efa427891044f92c1e8fd4e2df8" \
                                    "26aa10c466e7f642140825781d282b0e5112d93a562edb52d56d004b65393ddc" \
                                    "0d14d3baa8d4d8b68ec950575c3eea73887b08d26c7c395476f34bbcd9643124" \
                                    "d05f3c363c78480bef267a2c53c5e3b5e6280aff6358d2e421196eb2c63a908b" \
                                    "1e041363b2ddfe66eae36f84e765fb26e5fd1247a29ece2ed281edf958a3fa5f" \
                                    "32aba8971ca5c6c6cdd0ff53da6ffd7e34ad94e164957986a951606ad84f2fba" \
                                    "b0d25c72d8033a2e05f6ac622485795599b155fba5eb2afd2b92875dedb31b2c" \
                                    "ea56b543a5d74b46bae05b82debbee00340c36bfc56c32fedd2c084ef21fa366" \
                                    "3736425993ada34a5809068ad3164e6eeae45d368d7baec7596619f6fa3958e9" \
                                    "901ab28e4cac97efcca4564cc437bf9c0bd98a77624094abaeae44ff41193afe" \
                                    "94fa5908e7fc0860ddb7070105be5d9cd76d14156c74d5f1cdac18c7e3d7319f" \
                                    "86637d9fa3a874cea598330ccf553bb5c4042b5da3224e39e650b6c7387837f2" \
                                    "5878d9ae0630a2663b659975747e96eb6e1db632a6cb885e4dedea9558feda91" \
                                    "bd9d8cd2bd8e6b72f7492df9b622279d566b21744efac41ae98fce61882ea9cb" \
                                    "bc514d219e5281fc67a761b880133815f902ebcddf4b661d50baf50865333b41" \
                                    "44f7d6b076735b5a760fbc03f4d751a6cda212ba204119d9c24d726e4f21b33b" \
                                    "34aaf4a6e3ad7d0d06baece5a520d9d9ec7933ea87a2c8af60437d20a56b1759" \
                                    "d66c575737d182e6d4031d1c545eb9a8fcc48310ded76c1f565687b6ff5c28bc" \
                                    "2455650addebc2840309104045e1e2badf0c0ee61cf5c2a65be8b7771891badd" \
                                    "c2f333bf79c1934a51a49ed073a6fa7e5592a3939aa5f2b76677a0ad3c21e68f" \
                                    "1fdb8e2c4a439f6791b04bf0b6692b2bab81cecef8aeda81025cd52d78c11d75" \
                                    "7bfe9f95b387c7199d0673590b5a442b29fabc9fcf3178e1afed25a0fff378b4" \
                                    "400649d3bd5a4a2928fb4910484a68cf89f2a9c10be1379d18821765504f9613" \
                                    "45ae9a57ddcf165aeb8dfed462d0a56e440dfceb14ab8dfee01549557720c7b7" \
                                    "f38043f3f0567bbc2aecc13bb5d4937f9e99d16d0304bc28167ab6cb1f9169f8" \
                                    "d3fba21424306cfd42fb7cd977d06a100cfdb691038848eaba7cc5a7f665c7d6" \
                                    "879e754a918e6de90348a24543986dccd2163be4b997542e403ade97c7abc935" \
                                    "d10bc4232b585df8bf2f8b79877494a4e4615fec4d1f4445fb6f548d98e35fe2" \
                                    "49f06750dff66336604a62a1fb9fcf1582ef33c3f904e960eb384bc30e12b275" \
                                    "63edcaf5b5ff059fd6be4714319466b1c910bc34ea152fd56cac0e15f24d2813" \
                                    "bad91005c73b94b15bc8b9864221ad5299672c1098fbebe968ed388470f2192d" \
                                    "599f0e676bb0cc53cbefc0a3fb00406e4337bdef9d11e2fc5e42e1486468f407" \
                                    "da10758abc3de6662b85e44f298ddc3206ebf8c9fb447bab8ef3c2e29cfce0d6" \
                                    "aec559d36395de1af6db890affe055c4205029e89909a04d759508c1ad27574e" \
                                    "927d758612e8cd680d8c0587797a0c4f895402b4dcae2a3817ac5873fd8e6ab1" \
                                    "80adfdc93fd47e4e30a7cbb4d10efddb1bffa3eb7e2a9e2ee6bfdf6a05e7adcc" \
                                    "52cff5297c4879631859348f5bc67756c365d0c0dc0501e2161282f72c681ae5" \
                                    "9d47b038e026c8e7b262bd1539d34e306df30537a39d359d79e575a8f00f34e0" \
                                    "560ccd1f4f6eda060b74db41a54cbf6ce84b645fede4c65332e325d4468aaebc" \
                                    "8dfda2ec2358dfc66fe4939b69508133c11c6db79cab7a5645749e5a52e6ce5d" \
                                    "c208b6c21d4f07fa1cfb59346531355832785897bd002aeff6b459ceb434366e" \
                                    "c934542dc0489aec3e45b443d17521fb679359ae89577d0744686ce74ad0fa78" \
                                    "b550582b372c80cb8e4b6c4a1a3e9baa2adc719baee73a575bdcb05461b40dbd" \
                                    "8aaa542195954eaaa5c07ffbda14a8756b06779dcd34a8fc68360ec8b9de7507" \
                                    "5933ea45dba86c862c974ed4a32fa8302f50aac2dcfc9206e7e71ae04a42ad6f" \
                                    "75d98773dc94865de8a606c2ddd6d48e228847cf8bc19dc9f6d6a5e579f675b3" \
                                    "4f7e0c53e2f9095aa3c3ff3554b2aff92d87a133408e04b982db2a3d2b999c29" \
                                    "b6e892534c7ed999d87f13cda15a91c443369133ad7b3ccf7c34c29d6324240b" \
                                    "da4280b7d57eb39cb55a8028c3a9fa5c79635eb398fb5b59a8dc92586ebe5f90" \
                                    "5521a6a285e4256932d63cb22d0c5f61a80814b06e9b935e247a8dd32a70a51a" \
                                    "79f74f99bc713bee4c1ad366a444a505233f486556797dacee1938444c14b432" \
                                    "dbdb88e5035fcea690606c887ab2f1a5e620e1fdf7ca4b9bc8038c930aee33d3" \
                                    "0008369aa72690a6d5e637cca202035727cea7bd877738f351ab96cc8b37a290" \
                                    "d6abc3be1df1105cd55c1522c06e88c419bb91103b90744cf227b796f3e0d931" 
    return content_tls_appdata_all_cipher