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

class TestAes256GcmSha384:

    def test_with_key_file(self, test_pcap, expected_files_with_ssl):
        with mount_pcap(test_pcap, params=['-k', '{here}/keyfiles/aes256-gcm-sha384.key'.format(here=HERE)]) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl


    def test_without_key_file(self, test_pcap, expected_files_with_ssl_nokey):
        with mount_pcap(test_pcap) as mountpoint:
            assert get_file_list(mountpoint) == expected_files_with_ssl_nokey


    def test_read_raw_ssl_appdata(self, test_pcap, content_tls_appdata_all_cipher):
        with mount_pcap(test_pcap, params=['--show-all']) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2047_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2047_SSL'), 'rb') as f:
                content = f.read()
                data = binascii.hexlify(content)
                hexdata = str(data, 'UTF-8')
                assert(hexdata == content_tls_appdata_all_cipher)


    def test_read_processed_ssl_appdata(self, test_pcap, content_tls_appdata_all_plain):
        with mount_pcap(test_pcap, params=['--show-all', '-k', '{here}/keyfiles/aes256-gcm-sha384.key'.format(here=HERE)]) as mountpoint:
            files = get_file_list(mountpoint)
            assert('ssl/0-2047_SSL' in files)
            with open(os.path.join(mountpoint, 'ssl/0-2047_SSL'), 'rb') as f:
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
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pcaps/aes256-gcm-sha384.pcap')


@pytest.fixture
def expected_files():
    return sorted(['http/0-483', 'ssl/0-2047_SSL', 'tcp/0-4_tcp0'])


@pytest.fixture
def expected_files_with_ssl_nokey(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('http/0-483')
    return sorted(expected_files)


@pytest.fixture
def expected_files_with_ssl(expected_files):
    expected_files.remove('tcp/0-4_tcp0')
    expected_files.remove('ssl/0-2047_SSL')
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
                                    "32202d636970686572204145533235362d47434d2d534841333834202d6b6579" \
                                    "2073736c5f736372697074732f4d79526f6f7443412e6b6579202d6163636570" \
                                    "7420343433202d6465627567202d777777202d6b65796c6f6766696c65202f68" \
                                    "6f6d652f6178656c2f6165733235365f67636d5f7368613338342e6b6579200a" \
                                    "5365637572652052656e65676f74696174696f6e20495320737570706f727465" \
                                    "640a4369706865727320737570706f7274656420696e20735f73657276657220" \
                                    "62696e6172790a544c5376312e33202020203a544c535f4145535f3235365f47" \
                                    "434d5f53484133383420202020544c5376312e33202020203a544c535f434841" \
                                    "43484132305f504f4c59313330355f534841323536200a544c5376312e332020" \
                                    "20203a544c535f4145535f3132385f47434d5f53484132353620202020544c53" \
                                    "76312e32202020203a4145533235362d47434d2d534841333834202020202020" \
                                    "2020200a2d2d2d0a4369706865727320636f6d6d6f6e206265747765656e2062" \
                                    "6f74682053534c20656e6420706f696e74733a0a544c535f4145535f3132385f" \
                                    "47434d5f5348413235362020202020544c535f43484143484132305f504f4c59" \
                                    "313330355f53484132353620544c535f4145535f3235365f47434d5f53484133" \
                                    "3834202020200a4145533235362d47434d2d5348413338340a5369676e617475" \
                                    "726520416c676f726974686d733a2045434453412b5348413235363a45434453" \
                                    "412b5348413338343a45434453412b5348413531323a5253412d5053532b5348" \
                                    "413235363a5253412d5053532b5348413338343a5253412d5053532b53484135" \
                                    "31323a5253412b5348413235363a5253412b5348413338343a5253412b534841" \
                                    "3531323a45434453412b534841313a5253412b534841310a5368617265642053" \
                                    "69676e617475726520416c676f726974686d733a2045434453412b5348413235" \
                                    "363a45434453412b5348413338343a45434453412b5348413531323a5253412d" \
                                    "5053532b5348413235363a5253412d5053532b5348413338343a5253412d5053" \
                                    "532b5348413531323a5253412b5348413235363a5253412b5348413338343a52" \
                                    "53412b5348413531320a537570706f727465642067726f7570733a2078323535" \
                                    "31393a7365637032353672313a7365637033383472313a736563703532317231" \
                                    "3a6666646865323034383a6666646865333037320a5368617265642067726f75" \
                                    "70733a207832353531393a7365637032353672313a7365637033383472313a73" \
                                    "65637035323172313a6666646865323034383a6666646865333037320a2d2d2d" \
                                    "0a4e65772c20544c5376312e322c20436970686572206973204145533235362d" \
                                    "47434d2d5348413338340a53534c2d53657373696f6e3a0a2020202050726f74" \
                                    "6f636f6c20203a20544c5376312e320a20202020436970686572202020203a20" \
                                    "4145533235362d47434d2d5348413338340a2020202053657373696f6e2d4944" \
                                    "3a200a2020202053657373696f6e2d49442d6374783a2030313030303030300a" \
                                    "202020204d61737465722d4b65793a2046394338313833333839443530344646" \
                                    "4145464637324533313137414234354646363530433342353037354643333431" \
                                    "4136434443323634454136373133314133374335423633343637363642383334" \
                                    "334436323642374135413141304239450a2020202050534b206964656e746974" \
                                    "793a204e6f6e650a2020202050534b206964656e746974792068696e743a204e" \
                                    "6f6e650a2020202053525020757365726e616d653a204e6f6e650a2020202053" \
                                    "746172742054696d653a20313637323931323833320a2020202054696d656f75" \
                                    "742020203a20373230302028736563290a202020205665726966792072657475" \
                                    "726e20636f64653a203020286f6b290a20202020457874656e646564206d6173" \
                                    "746572207365637265743a207965730a2d2d2d0a20202030206974656d732069" \
                                    "6e207468652073657373696f6e2063616368650a2020203020636c69656e7420" \
                                    "636f6e6e65637473202853534c5f636f6e6e6563742829290a2020203020636c" \
                                    "69656e742072656e65676f746961746573202853534c5f636f6e6e6563742829" \
                                    "290a2020203020636c69656e7420636f6e6e6563747320746861742066696e69" \
                                    "736865640a20202031207365727665722061636365707473202853534c5f6163" \
                                    "636570742829290a20202030207365727665722072656e65676f746961746573" \
                                    "202853534c5f6163636570742829290a20202031207365727665722061636365" \
                                    "70747320746861742066696e69736865640a202020302073657373696f6e2063" \
                                    "6163686520686974730a202020312073657373696f6e206361636865206d6973" \
                                    "7365730a202020302073657373696f6e2063616368652074696d656f7574730a" \
                                    "202020302063616c6c6261636b20636163686520686974730a20202030206361" \
                                    "6368652066756c6c206f766572666c6f7773202831323820616c6c6f77656429" \
                                    "0a2d2d2d0a6e6f20636c69656e7420636572746966696361746520617661696c" \
                                    "61626c650a3c2f7072653e3c2f424f44593e3c2f48544d4c3e0d0a0d0a"
    return content_tls_appdata_all_plain


@pytest.fixture
def content_tls_appdata_all_cipher():
    content_tls_appdata_all_cipher = "000000000000000135a60c3778b7771e2cf21542887591cb6c04efeac904ad46" \
                                    "b107365e9cd2e160ee4bbcb577eb6e783ebc7099b3b1a4220d0001f93bbd14a2" \
                                    "df85b9475d4a90b324e330fab434038cfb6184072f1142fce61ef7c8be2fa381" \
                                    "968bc1bd567a28e3337068d864b08717317ae237cded7f7a54fd1edc8d12c8f8" \
                                    "950a863fbaefe7a5cc96352f5fe50ffc825c6486047c8fe8aaf159255e885a09" \
                                    "364fc4bb08ffc6d962a00cb2ef15ead3abe8cf91f92ef979ec1a024d3a75b7f4" \
                                    "e288eecac3f67b2b49b2262446811934d838fa1d03d01d4a4169f2bbfb1e7214" \
                                    "66c2d1687f6212d1ddc98ae8acfae4fdaadd684a3464ad70474267772d2647d3" \
                                    "8e6632b7b5b4d94189a764e377dde640754b6399b83d2bf78d98c17285fd5a07" \
                                    "bc2b05a597e211549d7bd66cf3b9d1ba53b082a2c8e7693ed02dc5a71a5ef4fc" \
                                    "b5de5d9cb62e1d3ee3401cd2b65bae31b8e16de5be0291a994d8f77501136e38" \
                                    "2413f9320f47f24a954e97172cac95ac304b22b88efd9f5ee935147b3b8c0c15" \
                                    "e9caaeb236f669b53ac81dfc753493630bf18e483354ac3503b6928f05e3033e" \
                                    "1c7b8877e870c800aa1808a78bbf6e2b2fd0da6d5ccccbaf05da33576a9e1cca" \
                                    "74524759f6e7bdb3d21d088b2c332f7812dbf6ad423fe2fdc1102fa602263da6" \
                                    "061f6d8198e725a841cd4736cf56240bf8609b294bead1381ec87d6c528ab1dc" \
                                    "90bb731a1e5b11d4f0b96f06da967c3604c19b0912ae50983a9387ecf0247074" \
                                    "6d321d1c1aed6a6bb1537794806ec1d59953e35512e48f0471b69e15630b7542" \
                                    "f054f5cfa8e2beeb362bdeb452bb8d2b515fc3499c094a88fa0e5aacb860895a" \
                                    "52449b35765a13eb4927e78ffc853f8861bc3ed6b3d25c808871381b1da899e8" \
                                    "f013615c7090a1d85f23803779011027dbed58d4cedb7c59dc23265f44947aa4" \
                                    "a352f23581c247ea995eedc483ed5d44b646185b714d2b3b890521305f37f0c4" \
                                    "c109c1ba5e17ce1bc83d0336e898d13d525504cd74720cbacf4dbd9685a6990f" \
                                    "6b6443fc235ca5313e4cae8f5cf6ad3154aa4227d4f2d32837a35bacdd63c850" \
                                    "eea0ac799c162ffd69b46c88b15d5ad272eea6bfb45da6624988bae29c1bc1f4" \
                                    "785ffce88a6ae8e8a7704a9cd14478531dcbe583ed6044623cc21120d9588001" \
                                    "270d973686e4fa0b50aa1a68e68a96b3b518c00fae2a49762609842fdfe53df4" \
                                    "f5882704285fb29cba1d2e2472966acd0315c9d5a7e9f7054305d39e7eb07fc2" \
                                    "795f327de4415072d11dd3cf0fc09b69916520af9895ab193e8f87fad9a1ee5c" \
                                    "a63cedb36a1fbbab210f4c01401fd462587cf90cee9c12de5ac4042f23f740f2" \
                                    "20e741d66f5cc9c4df33385b2525432ff0e1af822d894d3f0106bee9926863cf" \
                                    "0421c2b2420dc3422c7453799281d575c79f94ce7561cd3fe48b2a76ceceb1ff" \
                                    "164985f5759d28372d56cf04fbb7712c62eec29bae3a3b0c5f807f8bbdcde921" \
                                    "1c2983297cd20cbc6bd5a0d949fc6bb3cdf6c70409de5ce9b47f80e5b633c57e" \
                                    "7f91351ae731bacf3ac6f9061fa85e6cee5d0a2d5c4be5bc69dff75e03ff908a" \
                                    "2f725ee0e6353a3f29f894178a5f4d0507d978f3a14170ce443d9f7ed2553ad3" \
                                    "a2698251ce568e8bda32e5f6d032f7c76f108958fd51e023e372000e0647594c" \
                                    "b7a4c4e8fe56043a17db255c1ee0f11a2e04734885ea7c60a91098f0493c8c4a" \
                                    "dc427a1cadea9d5ea94187d9740f370ea0b2f2b4561331ee5cde60ade12a721d" \
                                    "d538ab8c0c0c66b88a098ba1fd65ead955ca4a032c11c3b538f6d39faaed5d18" \
                                    "cf03450887f838ebf892f75d72e1fa1af75e3365a766bb5ee70361d13f96937d" \
                                    "4751c46baabaabf47aec45c35077f9f2f6ffd3f9adfe9b5324777fbb71289612" \
                                    "c4bdb5b3b570eac03a3add0a05c6bdf938f264d1c272bfca113fe8af787ea2d2" \
                                    "4bd6c1e0971ebbc3bea2f2eac30d66ecdfc0641198778129ff1b82e9ae91d5cd" \
                                    "c55ec4bbdc80c6c2167ad52059bffdd7628dd3c495bb970177dd3bf3d393ef82" \
                                    "155566046097c69cc7941d1863afd6945995794b82fd160fe359ebb9bac2836e" \
                                    "c6d973152133c544cf153412fadb5021902211957269b04fc38a8abcbb375bc0" \
                                    "d8685f154a33e773fbba02ddd6aeaafc986d98362b4dfea83981ea32987efeb0" \
                                    "f193c7951e712e56434f17d403fbc6ffaba35f36544823f3ce7f7ae6dc80e101" \
                                    "c65693a284fa1684fc1d5c056c066d3a6b13bb08456b3cf81b52f2e613f891b0" \
                                    "dabbb2c03d2ea017ad8522a758f15ef529af6bb549fe25eff3bdbeccd8818536" \
                                    "1b82132840519fcbca2fd75dc83172e039840f6840f771403c58d693d365e792" \
                                    "64d2de6168bbc6933105177b69aa56b4df7f14af3e62c9bd68b06d9430116170" \
                                    "2ec9d3edfbc4565dd695d492857027658a8ef5304d9bd21a208228581867f447" \
                                    "2a723ad49603def2948f7378da3b540730a03c56a57a6310aabb6668c9ed6dae" \
                                    "058f39aaa72d9e1395b885dae6d92b9cab858f0678190278fc45400765e5db63" \
                                    "ee154019753e2c3d2e8eebc509d8a903ad77f5523153887d4d366c6775db5c1b" \
                                    "cd03f0f2cc2588bc98c64e237958beb3516e0d7aebc119585356acad771c1182" \
                                    "9a3ad43b9aee1194a26965f9d269dae3caa53a91e31aa8369fa87a3d375894ac" \
                                    "78a6c42ac8d0d79fa99d7da7d1169601a73372c780ef5d247a7ffddedb9fe807" \
                                    "9f640902d302b935afd80497e16875b29a1b74d364da260f7ca1c5589ee92ad1" \
                                    "429a630e1e88c61143e4564780d5a3492316b0d49a87a455d94384b03521a8cf" \
                                    "d4fedde13bea0dce3cf0c56b30f6fa136f9212dfeec9139e38f9812d07ba7c87" \
                                    "a371d06d285c2666be0e1006e8dfe89c33987a4b010891e4f1c1bd78a7678eec" \
                                    "65e5b65c1061f2d26a23813a4b338263e1d96845669127bd87904df39a8687fe" \
                                    "020f31fe3ee9de84084a3beac268d984c107fd3954e3af8649b497f6f66b6c7b" \
                                    "b17a534b2823e0302d1925a3bd7f84ae6f93cae1f2bf55aec7c452ede5fa1b1e" \
                                    "6a9dc7e7ffcce0b54f877176f0cdce7c8fa831e0e8f4b5860136275eacc5fbea" \
                                    "5845f0eaf4d47b3de801bba70eb389ac7fb97473dd34a62758adb2e767e26e7c" \
                                    "7dbacebb9746c60108bfce9b7d34460533a6ca22f399f4a9b473d37fe4dd704e" \
                                    "3efb3552cbf6a87bd95f1d3ab7cdff9b544c9c345b416d5e4b770085b135ab15" \
                                    "e4dd6d0c8e8bb0a682b6181651685324d9df80884e814177c662b81a280e98b6" \
                                    "1c390101940424e77f4a7b12a34ca6645c3f77f66f2015c6c338b41ce2c2649f" \
                                    "2fb5fc0fb8e1a81ef9cc0e863085822a20d726c64a239e466e5cd31e124b8983" \
                                    "888f1ca4097ba52b04bf51e41be20bcae02defb327c47c3bcf7c7e01202a5d19" \
                                    "8d909421f6df3ae4cc97173ae3e957045dc8febfa7d6038f0611f67bd976ef8d" \
                                    "6e07bbd1adca88a77e2ee0d35d823289fbc8aa47c6a74243e93769428477278a" \
                                    "d0a2ea9b27d5dbde1da6fb05c73727a177b93d5d78dd76faf4530e91dd31ef28" \
                                    "cb4e0671fc079275ac1cd38443"
    return content_tls_appdata_all_cipher