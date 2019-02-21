#include "ssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rc4.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>

#include "../filefactory.h"
#include "../logging.h"


namespace {
    //TODO: variable size get them in static functions?
    size_t const CLIENT_RANDOM_SIZE = 32;
    size_t const SERVER_RANDOM_SIZE = 32;
    size_t const MAC_SIZE = 16;
    size_t const KEY_SIZE = 16;
}


std::vector<pcapfs::FilePtr> pcapfs::SslFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    //Step 1: detect ssl stream by checking for dst Port 443
    //TODO: other detection method?
    if (filePtr->getProperty("dstPort") != "443") {
        return resultVector;
    }

    //Step 2: Get key material for SSL stream
    size_t size = 0;
    size_t numElements = filePtr->connectionBreaks.size();
    bool processedSSLHandshake = false;
    pcpp::Packet *packet = nullptr;

    Bytes clientRandom(CLIENT_RANDOM_SIZE);
    Bytes serverRandom(SERVER_RANDOM_SIZE);
    Bytes masterSecret;
    uint64_t clientEncryptedData = 0;
    uint64_t serverEncryptedData = 0;
    std::string cipherSuite = "";
    bool clientChangeCipherSpec = false;
    bool serverChangeCipherSpec = false;

    std::shared_ptr<SslFile> resultPtr = nullptr;

    //Step 3: process all logical breaks in underlying virtual file
    for (unsigned int i = 0; i < numElements; ++i) {
        LOG_DEBUG << "processing element " << std::to_string(i) << " of " << std::to_string(numElements);
        uint64_t &offset = filePtr->connectionBreaks.at(i).first;

        //get correct size (depending on element processed)
        if (i == numElements - 1) {
            size = filePtr->getFilesizeRaw() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        //Step 4: one logical fragment may contain multiple ssl layer messages
        pcpp::SSLLayer *sslLayer = sslLayer->createSSLMessage((uint8_t *) data.data() + offset, size, nullptr, packet);
        uint64_t offsetInLogicalFragment = 0;
        bool connectionBreakOccured = true;

        while (sslLayer != nullptr) {
            pcpp::SSLRecordType recType = sslLayer->getRecordType();

            //Step 5: parse the corresponding ssl message
            if (recType == pcpp::SSL_HANDSHAKE) {
                pcpp::SSLHandshakeLayer *handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(sslLayer);

                for (uint64_t j = 0; j < handshakeLayer->getHandshakeMessagesCount(); ++j) {
                    pcpp::SSLHandshakeMessage *handshakeMessage = handshakeLayer->getHandshakeMessageAt(j);
                    pcpp::SSLHandshakeType handshakeType = handshakeMessage->getHandshakeType();

                    if (handshakeType == pcpp::SSL_CLIENT_HELLO) {
                        pcpp::SSLClientHelloMessage *clientHelloMessage =
                                dynamic_cast<pcpp::SSLClientHelloMessage *>(handshakeMessage);
                        memcpy(clientRandom.data(), clientHelloMessage->getClientHelloHeader()->random,
                               CLIENT_RANDOM_SIZE);
                        offsetInLogicalFragment += clientHelloMessage->getMessageLength();
                    } else if (handshakeType == pcpp::SSL_SERVER_HELLO) {
                        pcpp::SSLServerHelloMessage *serverHelloMessage =
                                dynamic_cast<pcpp::SSLServerHelloMessage *>(handshakeMessage);

                        memcpy(serverRandom.data(), serverHelloMessage->getServerHelloHeader()->random,
                               SERVER_RANDOM_SIZE);

                        offsetInLogicalFragment += serverHelloMessage->getMessageLength();
                        LOG_DEBUG << "found server hello message";
                        //TODO: Segfault in cipher suite?!
                        LOG_DEBUG << "chosen cipher suite: " << serverHelloMessage->getCipherSuite()->asString();
                        if (serverHelloMessage->getCipherSuite()) {
                            cipherSuite = serverHelloMessage->getCipherSuite()->asString();
                        } else {
                            cipherSuite = "UNKNOWN_CIPHER_SUITE";
                        }
                        processedSSLHandshake = true;
                        LOG_DEBUG << "handshake completed";
                    } else if (handshakeType == pcpp::SSL_CERTIFICATE) {
                        pcpp::SSLCertificateMessage *certificateMessage =
                                dynamic_cast<pcpp::SSLCertificateMessage *>(handshakeMessage);
                        offsetInLogicalFragment += certificateMessage->getMessageLength();
                        //TODO: sslcert as a virtual file
                        LOG_DEBUG << "found certificiate!";
                    } else if (handshakeType == pcpp::SSL_SERVER_DONE) {
                        pcpp::SSLServerHelloDoneMessage *serverHelloDoneMessage =
                                dynamic_cast<pcpp::SSLServerHelloDoneMessage *>(handshakeMessage);
                        offsetInLogicalFragment += serverHelloDoneMessage->getMessageLength();
                        LOG_DEBUG << "found server hello done!";
                    } else if (handshakeType == pcpp::SSL_CLIENT_KEY_EXCHANGE) {
                        pcpp::SSLClientKeyExchangeMessage *clientKeyExchangeMessage =
                                dynamic_cast<pcpp::SSLClientKeyExchangeMessage *>(handshakeMessage);
                        offsetInLogicalFragment += clientKeyExchangeMessage->getMessageLength();
                        LOG_DEBUG << "found client key exchange with length " <<
                        clientKeyExchangeMessage->getClientKeyExchangeParamsLength();
                    } else if (handshakeType == pcpp::SSL_HANDSHAKE_UNKNOWN) {
                        //TODO: right now assuming these are encrypted handshake messages;
                        pcpp::SSLUnknownMessage *unknownMessage =
                                dynamic_cast<pcpp::SSLUnknownMessage *>(handshakeMessage);
                        offsetInLogicalFragment += unknownMessage->getMessageLength();
                        LOG_DEBUG << "encrypted handshake message";
                        if (isClientMessage(i) && clientChangeCipherSpec) {
                            clientEncryptedData += unknownMessage->getMessageLength();
                            LOG_DEBUG << "client encrypted " << std::to_string(clientEncryptedData);
                        } else if (serverChangeCipherSpec) {
                            serverEncryptedData += unknownMessage->getMessageLength();
                            LOG_DEBUG << "server encrypted " << std::to_string(serverEncryptedData);
                        }
                    }

                }
                //TODO: metadata followed by application data without connection break?!
            } else if (recType == pcpp::SSL_CHANGE_CIPHER_SPEC) {
                if (isClientMessage(i)) {
                    LOG_DEBUG << "client starting encryption now!";
                    clientChangeCipherSpec = true;
                } else {
                    LOG_DEBUG << "server starting encryption now!";
                    serverChangeCipherSpec = true;
                }

                pcpp::SSLChangeCipherSpecLayer *changeCipherSpecLayer =
                        dynamic_cast<pcpp::SSLChangeCipherSpecLayer *>(sslLayer);
                offsetInLogicalFragment += (changeCipherSpecLayer->getDataLen() +
                                            changeCipherSpecLayer->getHeaderLen());

            } else if (recType == pcpp::SSL_APPLICATION_DATA) {
                pcpp::SSLApplicationDataLayer *applicationDataLayer =
                        dynamic_cast<pcpp::SSLApplicationDataLayer *>(sslLayer);
                uint64_t encryptedDataLen = applicationDataLayer->getEncrpytedDataLen();
                uint64_t completeSSLLen = applicationDataLayer->getHeaderLen();
                uint64_t bytesBeforeEncryptedData = completeSSLLen - encryptedDataLen;
                //create ssl application file
                //TODO: does client always send first?
                if (resultPtr == nullptr) {
                    resultPtr = std::make_shared<SslFile>();
                    //search for master secret in candidates
                    if (processedSSLHandshake) {
                        Bytes masterSecret = searchCorrectMasterSecret((char *) clientRandom.data(), idx);
                        if (!masterSecret.empty()) {
                            Bytes keyMaterial = createKeyMaterial((char *) masterSecret.data(),
                                                                  (char *) clientRandom.data(),
                                                                  (char *) serverRandom.data());

                            //TODO: not good to add sslkey file directly into index!!!
                            std::shared_ptr<SSLKeyFile> keyPtr = SSLKeyFile::createKeyFile(keyMaterial);
                            idx.insert(keyPtr);
                            resultPtr->keyIDinIndex = keyPtr->getIdInIndex();
                            resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);

                        }
                    }

                    resultPtr->setOffsetType(filePtr->getFiletype());
                    resultPtr->setFiletype("ssl");
                    resultPtr->cipherSuite = cipherSuite;
                    resultPtr->setFilename("SSL");
                    resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
                    resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
                    resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
                    resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
                    //resultPtr->setProperty("ciphersuite", cipherSuite);
                    resultPtr->setProperty("protocol", "ssl");
                    resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
                    if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                        resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
                    }
                }

                if (connectionBreakOccured) {
                    resultPtr->connectionBreaks.push_back(
                            {resultPtr->getFilesizeRaw(), filePtr->connectionBreaks.at(i).second});
                    connectionBreakOccured = false;
                }

                //each application data is part of the stream
                SimpleOffset soffset;
                soffset.id = filePtr->getIdInIndex();
                soffset.start = offset + bytesBeforeEncryptedData + offsetInLogicalFragment;
                soffset.length = encryptedDataLen - MAC_SIZE;
                //if size is a mismatch => ssl packet is malformed
                //TODO: Better detection of malformed ssl packets
                if (soffset.length > sslLayer->getDataLen()) {
                    break;
                }
                resultPtr->offsets.push_back(soffset);
                //TODO: processedsize should be set
                resultPtr->setFilesizeRaw(resultPtr->getFilesizeRaw() + soffset.length);

                LOG_DEBUG << "found server app data";
                if (isClientMessage(i) && clientChangeCipherSpec) {
                    resultPtr->previousBytes.push_back(clientEncryptedData);
                    clientEncryptedData += encryptedDataLen;
                    resultPtr->keyForFragment.push_back(0);
                    LOG_DEBUG << "client encrypted " << std::to_string(clientEncryptedData);
                } else if (!isClientMessage(i) && serverChangeCipherSpec) {
                    resultPtr->previousBytes.push_back(serverEncryptedData);
                    serverEncryptedData += encryptedDataLen;
                    resultPtr->keyForFragment.push_back(1);
                    LOG_DEBUG << "server encrypted " << std::to_string(serverEncryptedData);
                }

                offsetInLogicalFragment += completeSSLLen;
            }

            LOG_DEBUG << "OFFSET IN LOG FRAGMENT: " << std::to_string(offsetInLogicalFragment);
            sslLayer->parseNextLayer();
            sslLayer = dynamic_cast<pcpp::SSLLayer *>(sslLayer->getNextLayer());
        }
        //store ssl stream in result vector
    }
    //TODO: multiple ssl streams in one tcp stream?!
    if (resultPtr != nullptr) {
        resultVector.push_back(resultPtr);
    }
    return resultVector;
}

//TODO: What does this function?
pcapfs::Bytes pcapfs::SslFile::searchCorrectMasterSecret(char *clientRandom,
                                                         const Index &idx) {

    std::vector<pcapfs::FilePtr> keyFiles = idx.getCandidatesOfType("sslkey");

    for (auto &keyFile: keyFiles) {
        std::shared_ptr<SSLKeyFile> sslKeyFile = std::dynamic_pointer_cast<SSLKeyFile>(keyFile);

        if (memcmp((char *) sslKeyFile->getClientRandom().data(), clientRandom, sslKeyFile->getClientRandom().size()) == 0) {
            return sslKeyFile->getMasterSecret();
        }
    }

    return Bytes();
}



/*
 * Decryption Engine:
 * We use pcap plus plus to detect the matching cipher. Pcap plus plus does provide the IANA mapping via the method
 *   pcpp::SSLCipherSuite::getCipherSuiteByName(std::__cxx11::string cipherSuite)
 * 
 * Decryption is handled by openssl bindings since pcap plus plus provides only parsing for SSL/TLS.
 * 
 * OpenSSL Ciphers vs standard (good to know):
 * https://testssl.sh/openssl-iana.mapping.html
 * 
 * symetric ssl encryption enum in pcap plus plus:
 * https://seladb.github.io/PcapPlusPlus-Doc/Documentation/a00202.html#ac4f9e906dad88c5eb6a34390e5ea54b7
 * 
 */
pcapfs::Bytes pcapfs::SslFile::decryptData(uint64_t padding, size_t length, char *data, char *key) {
    pcpp::SSLCipherSuite *cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByName(this->cipherSuite);
    switch (cipherSuite->getSymKeyAlg()) {
        
        case pcpp::SSL_SYM_RC4_128:
            /*
             * This cipher flag SSL_SYM_RC4_128 in pcap plus plus should be able to decrypt the following cipher suites (all ciphers with RC4_128 bit keys):
             * 
             * Cipher Suite     Name (OpenSSL)              KeyExch.        Encryption 	    Bits        Cipher Suite Name (IANA)
             * [0x05]           RC4-SHA                     RSA             RC4             128         TLS_RSA_WITH_RC4_128_SHA
             * [0x18]           ADH-RC4-MD5                 DH              RC4             128         TLS_DH_anon_WITH_RC4_128_MD5
             * [0x1e]                                       FORTEZZA        FORTEZZA_RC4    128         SSL_FORTEZZA_KEA_WITH_RC4_128_SHA
             * [0x20]           KRB5-RC4-SHA                KRB5            RC4             128         TLS_KRB5_WITH_RC4_128_SHA
             * [0x24]           KRB5-RC4-MD5                KRB5            RC4             128         TLS_KRB5_WITH_RC4_128_MD5
             * [0x66]           DHE-DSS-RC4-SHA             DH              RC4             128         TLS_DHE_DSS_WITH_RC4_128_SHA
             * [0x8a]           PSK-RC4-SHA                 PSK             RC4             128         TLS_PSK_WITH_RC4_128_SHA
             * [0x8e]                                       PSK/DHE         RC4             128         TLS_DHE_PSK_WITH_RC4_128_SHA
             * [0x92]                                       PSK/RSA         RC4             128         TLS_RSA_PSK_WITH_RC4_128_SHA
             * [0xc002]         ECDH-ECDSA-RC4-SHA          ECDH/ECDSA      RC4             128         TLS_ECDH_ECDSA_WITH_RC4_128_SHA
             * [0xc007]         ECDHE-ECDSA-RC4-SHA         ECDH            RC4             128         TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
             * [0xc00c]         ECDH-RSA-RC4-SHA            ECDH/RSA        RC4             128         TLS_ECDH_RSA_WITH_RC4_128_SHA
             * [0xc011]         ECDHE-RSA-RC4-SHA           ECDH            RC4             128         TLS_ECDHE_RSA_WITH_RC4_128_SHA
             * [0xc016]         AECDH-RC4-SHA               ECDH            RC4             128         TLS_ECDH_anon_WITH_RC4_128_SHA
             * [0xc033]         ECDHE-PSK-RC4-SHA           PSK/ECDHE       RC4             128         TLS_ECDHE_PSK_WITH_RC4_128_SHA
             * [0x010080]       RC4-MD5                     RSA             RC4             128         SSL_CK_RC4_128_WITH_MD5
             * [0x020080]       EXP-RC4-MD5                 RSA(512)        RC4             40, export  SSL_CK_RC4_128_EXPORT40_WITH_MD5
             */
            return decryptRc4(padding, length, data, key);
        
        
        case pcpp::SSL_SYM_RC
        default:
            LOG_ERROR << "unsupported encryption found in ssl cipher suite: " << cipherSuite;
    }
    return Bytes();
}


pcapfs::Bytes pcapfs::SslFile::decryptRc4(uint64_t padding, size_t length, char *data, char *key) {

    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();

    //decrypt data using keys and RC4
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    const unsigned char *keyToUse = reinterpret_cast<unsigned char *>(key);
    RC4_KEY rc4Key;
    RC4_set_key(&rc4Key, KEY_SIZE, keyToUse);
    RC4(&rc4Key, dataToDecrypt.size(), dataToDecryptPtr, decryptedData.data());

    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);

    return decryptedData;
}

//TODO: not abstract enough to handle all ciphers
pcapfs::Bytes pcapfs::SslFile::createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom) {
    //TODO: for some cipher suites this is done by using hmac and sha256 (need to specify these!)
    size_t KEY_MATERIAL_SIZE = 128;
    size_t const LABEL_SIZE = 13;
    size_t const SERVER_RANDOM_SIZE = 32;
    size_t const CLIENT_RANDOM_SIZE = 32;
    char const LABEL[14] = "key expansion";

    size_t seedSize = LABEL_SIZE + SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE;
    Bytes seed(seedSize);
    memcpy(&seed[0], LABEL, LABEL_SIZE);
    memcpy(&seed[LABEL_SIZE], serverRandom, SERVER_RANDOM_SIZE);
    memcpy(&seed[LABEL_SIZE + SERVER_RANDOM_SIZE], clientRandom, CLIENT_RANDOM_SIZE);

    Bytes keyMaterial(KEY_MATERIAL_SIZE);
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0)
        std::cerr << "Error1!" << std::endl;
    if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0)
        std::cerr << "Error2!" << std::endl;
    if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, masterSecret, 48) <= 0)
        std::cerr << "Error3!" << std::endl;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seedSize) <= 0)
        std::cerr << "Error4!" << std::endl;
    if (EVP_PKEY_derive(pctx, keyMaterial.data(), &KEY_MATERIAL_SIZE) <= 0)
        std::cerr << "Error5!" << std::endl;
    ERR_print_errors_fp(stderr);

    return keyMaterial;
}


size_t pcapfs::SslFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: support to decrypt CBC etc. stuff... Maybe decrypt all of the data or return parts? Depens on mode of operation
    //TODO: split read into readStreamcipher, readCFB, readCBC...
    size_t fragment = 0;
    size_t posInFragment = 0;
    size_t position = 0;

    // seek to start_offset
    while (position < startOffset) {
        position += offsets[fragment].length;
        fragment++;
    }

    if (position > startOffset) {
        fragment--;
        posInFragment = offsets[fragment].length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    // start copying
    while (position < startOffset + length && fragment < offsets.size()) {
        size_t toRead = std::min(offsets[fragment].length - posInFragment, length - (position - startOffset));
        //TODO: is start=0 really good for missing data?
        if (offsets[fragment].start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            LOG_DEBUG << "filling data";
            memset(buf + (position - startOffset), 0, toRead);
        } else {
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->offsets.at(fragment).id});
            pcapfs::Bytes toDecrypt(this->offsets.at(fragment).length);
            filePtr->read(offsets.at(fragment).start, offsets.at(fragment).length, idx, (char *) toDecrypt.data());

            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                pcapfs::Bytes decrypted;
                //TODO: KEY_SIZE and MAC_SIZE in SSLKeyFile?!
                std::shared_ptr<SSLKeyFile> keyPtr = std::dynamic_pointer_cast<SSLKeyFile>(
                        idx.get({"sslkey", keyIDinIndex}));
                if (isClientMessage(keyForFragment.at(fragment))) {
                    decrypted = decryptData(previousBytes[fragment], toDecrypt.size(), (char *) toDecrypt.data(),
                                            (char *) keyPtr->getClientWriteKey(16, 16).data());
                } else {
                    decrypted = decryptData(previousBytes[fragment], toDecrypt.size(), (char *) toDecrypt.data(),
                                            (char *) keyPtr->getServerWriteKey(16, 16).data());
                }
                memcpy(buf + (position - startOffset), decrypted.data() + posInFragment, toRead);
            } else {
                memcpy(buf + (position - startOffset), toDecrypt.data() + posInFragment, toRead);
            }
        }

        // set run variables in case next fragment is needed
        position += toRead;
        fragment++;
        posInFragment = 0;
    }

    if (startOffset + length < filesizeRaw) {
        return length;
    } else {
        return filesizeRaw - startOffset;
    }
}


bool pcapfs::SslFile::isClientMessage(uint64_t i) {
    if (i % 2 == 0) {
        return true;
    } else {
        return false;
    }
}


bool pcapfs::SslFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ssl", pcapfs::SslFile::create, pcapfs::SslFile::parse);


void pcapfs::SslFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << cipherSuite;
    archive << keyIDinIndex;
    archive << previousBytes;
    archive << keyForFragment;
}


void pcapfs::SslFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    archive >> cipherSuite;
    archive >> keyIDinIndex;
    archive >> previousBytes;
    archive >> keyForFragment;
}
