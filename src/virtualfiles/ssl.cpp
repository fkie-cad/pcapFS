#include "ssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rc4.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>

#include "../filefactory.h"
#include "../logging.h"
#include "../crypto/decryptSymmetric.h"


namespace {
    //TODO: variable size get them in static functions?
    size_t const CLIENT_RANDOM_SIZE = 32;
    size_t const SERVER_RANDOM_SIZE = 32;
    //MAC size may vary? AES_CBC should have 20 Bytes MAC 
    //size_t const MAC_SIZE = 16;
    //size_t const KEY_SIZE = 16;
}


std::vector<pcapfs::FilePtr> pcapfs::SslFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    //Step 1: detect ssl stream by checking for dst Port 443
    //TODO: other detection method -> config file vs heuristic?
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
    pcpp::SSLVersion sslVersion;
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
                            
                            /*
                             * Those values are used for the decryption in decryptData() function
                             */
                            
                            cipherSuite = serverHelloMessage->getCipherSuite()->asString();
                            sslVersion = sslLayer->getRecordVersion();
                            
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
                                                                  (char *) serverRandom.data(),
                                                                  sslVersion
                                                                 );

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
                    resultPtr->sslVersion = sslVersion;
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
                
                /*
                 * This is an important change:
                 * We keep the hmac (and other stuff if there is any) now behind every message.
                 * 
                 * This is a workaround for determining padding sizes in AES CBC and will help in future
                 * to detect whether if a packet is signed correctly or not
                 * 
                 */
                //soffset.length = encryptedDataLen - MAC_SIZE;
                soffset.length = encryptedDataLen;
                
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

//Returns the correct Master Secret out of a bunch of candidates
pcapfs::Bytes pcapfs::SslFile::searchCorrectMasterSecret(char *clientRandom, const Index &idx) {

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
pcapfs::Bytes pcapfs::SslFile::decryptData(uint64_t padding, size_t length, char *data, char* key_material, bool isClientMessage) {
    pcpp::SSLCipherSuite *cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByName(this->cipherSuite);
    switch (cipherSuite->getSymKeyAlg()) {
        
        /*
         * RC4 in SSL/TLS implemented cipher suites are decrypted here:
         */
        
        case pcpp::SSL_SYM_RC4_128:
        {
            /*
             * This cipher flag SSL_SYM_RC4_128 in pcap plus plus should be able to decrypt the following cipher suites (all ciphers with RC4_128 bit keys):
             * Hint: Although this is correct in theory, in practive some of the ciphers are not supported by pcap++ nor openssl
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
             */
            LOG_DEBUG << "Decrypting SSL_SYM_RC4_128 using " << " KEY: " << key_material << " length: " << length << " padding: " << padding << " data: " << data << std::endl;
            
            const int mac_size = 16;
            const int key_size = 16;
            const int iv_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];
            unsigned char client_write_IV[iv_size];
            unsigned char server_write_IV[iv_size];
            
            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
            memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_RC4_128(padding, length, data, client_write_MAC_key, client_write_key, client_write_IV);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_RC4_128(padding, length, data, server_write_MAC_key, server_write_key, server_write_IV);
                
            }
        }
            
            
        
        case pcpp::SSL_SYM_RC4_64:
        {
            //TODO: maybe the last 64 bytes have to be zero to have 128bit rc4
            LOG_DEBUG << "Decrypting SSL_SYM_RC4_64 using " << " KEY: " << key_material << " length: " << length << " padding: " << padding << " data: " << data << std::endl;
            LOG_ERROR << "unsupported operation" << std::endl;
            const int mac_size = 16;
            const int key_size = 8;
            //const int iv_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];
            //unsigned char client_write_IV[iv_size];
            //unsigned char server_write_IV[iv_size];
            
            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            //memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
            //memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_RC4_64(padding, length, data, client_write_MAC_key, client_write_key, NULL);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_RC4_64(padding, length, data, server_write_MAC_key, server_write_key, NULL);
                
            }
        }
            
            
        case pcpp::SSL_SYM_RC4_56:
        {
            //TODO: maybe the last 64 bytes have to be zero to have 128bit rc4
            LOG_DEBUG << "Decrypting SSL_SYM_RC4_64 using " << " KEY: " << key_material << " length: " << length << " padding: " << padding << " data: " << data << std::endl;
            LOG_ERROR << "unsupported operation" << std::endl;
            const int mac_size = 16;
            const int key_size = 7;
            //const int iv_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];
            //unsigned char client_write_IV[iv_size];
            //unsigned char server_write_IV[iv_size];
            
            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            //memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
            //memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_RC4_56(padding, length, data, client_write_MAC_key, client_write_key, NULL);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_RC4_56(padding, length, data, server_write_MAC_key, server_write_key, NULL);
                
            }
        }
            
            
        case pcpp::SSL_SYM_RC4_128_EXPORT40:
        {
            //TODO: maybe the last 64 bytes have to be zero to have 128bit rc4
            LOG_DEBUG << "Decrypting SSL_SYM_RC4_128_EXPORT40 using " << " KEY: " << key_material << " length: " << length << " padding: " << padding << " data: " << data << std::endl;
            LOG_ERROR << "unsupported operation" << std::endl;
            const int mac_size = 16;
            const int key_size = 5;
            //const int iv_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];
            //unsigned char client_write_IV[iv_size];
            //unsigned char server_write_IV[iv_size];
            
            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            //memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
            //memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_RC4_40(padding, length, data, client_write_MAC_key, client_write_key, NULL);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_RC4_40(padding, length, data, server_write_MAC_key, server_write_key, NULL);
                
            }
        }          
            
        case pcpp::SSL_SYM_RC4_40:
            /* 
             * Cipher Suite     Name (OpenSSL)              KeyExch.        Encryption 	    Bits        Cipher Suite Name (IANA)
             * [0x020080]       EXP-RC4-MD5                 RSA(512)        RC4             40, export  SSL_CK_RC4_128_EXPORT40_WITH_MD5
             * 
             * this entry has to be checked, it should be a RC4 128 bit implementation with the last 88 bytes set to zero.
             */            
            {
                //TODO: maybe the last 64 bytes have to be zero to have 128bit rc4
                LOG_DEBUG << "Decrypting SSL_SYM_RC4_128_EXPORT40 using " << " KEY: " << key_material << " length: " << length << " padding: " << padding << " data: " << data << std::endl;
                LOG_ERROR << "unsupported operation" << std::endl;
                const int mac_size = 16;
                const int key_size = 5;
                //const int iv_size = 16;
                
                unsigned char client_write_MAC_key[mac_size];
                unsigned char server_write_MAC_key[mac_size];
                unsigned char client_write_key[key_size];
                unsigned char server_write_key[key_size];
                //unsigned char client_write_IV[iv_size];
                //unsigned char server_write_IV[iv_size];
                
                memcpy(client_write_MAC_key,    key_material,                                   mac_size);
                memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
                memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
                memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
                //memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
                //memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
                
                if(isClientMessage) {
                    /*
                     * This is a client message
                     */
                    
                    return Crypto::decrypt_RC4_40(padding, length, data, client_write_MAC_key, client_write_key, NULL);
                    
                } else {
                    /*
                     * This is a server message, so we use server key etc.
                     */
                    
                    return Crypto::decrypt_RC4_40(padding, length, data, server_write_MAC_key, server_write_key, NULL);
                    
                }
            }               
            
        case pcpp::SSL_SYM_AES_128_CBC:
        {
            /*
             * See https://www.ietf.org/rfc/rfc5246.txt, Page 26
             * 
             * 256_CBC should have the same except key material, 32 instead of 16, IV should be 16 bytes. (Page 84)
             */
            
            unsigned char client_write_MAC_key[20];
            unsigned char server_write_MAC_key[20];
            unsigned char client_write_key[16];
            unsigned char server_write_key[16];
            unsigned char client_write_IV[16];
            unsigned char server_write_IV[16];
            
            /*
             * Copy all bytes from the key material into our split key material.
             */
            
            memcpy(client_write_MAC_key,    key_material,           20);
            memcpy(server_write_MAC_key,    key_material+20,        20);
            memcpy(client_write_key,        key_material+40,        16);
            memcpy(server_write_key,        key_material+40+16,     16);
            memcpy(client_write_IV,         key_material+40+32,     16);
            memcpy(server_write_IV,         key_material+72+16,     16);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                LOG_DEBUG << "decrypt_AES_128_CBC called with a client packet" << std::endl;
                return Crypto::decrypt_AES_128_CBC(padding, length, data, client_write_MAC_key, client_write_key, client_write_IV);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                LOG_DEBUG << "decrypt_AES_128_CBC called with a server packet" << std::endl;
                return Crypto::decrypt_AES_128_CBC(padding, length, data, server_write_MAC_key, server_write_key, server_write_IV);
                
            }
            
        }
            
        case pcpp::SSL_SYM_AES_256_CBC:
        {
            /*
             * See https://www.ietf.org/rfc/rfc5246.txt, Page 26
             * 
             * 256_CBC should have the same except key material, 32 instead of 16, IV should be 16 bytes. (Page 84)
             */
            
            const int mac_size = 16;
            const int key_size = 32;
            const int iv_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];
            unsigned char client_write_IV[iv_size];
            unsigned char server_write_IV[iv_size];
            
            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            memcpy(client_write_IV,         key_material + 2*mac_size+2*key_size,           iv_size);
            memcpy(server_write_IV,         key_material + 2*mac_size+2*key_size+iv_size,   iv_size);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_AES_256_CBC(padding, length, data, client_write_MAC_key, client_write_key, client_write_IV);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_AES_256_CBC(padding, length, data, server_write_MAC_key, server_write_key, server_write_IV);
                
            }
            
        }
        
        
        case pcpp::SSL_SYM_AES_128_GCM:
        {
            
            printf("key_material:\n");
            BIO_dump_fp (stdout, (const char *) key_material, 128);
            
            unsigned char client_write_key[16];
            unsigned char server_write_key[16];
            unsigned char client_write_IV[4];
            unsigned char server_write_IV[4];
            
            /*
             * Copy all bytes from the key material into our split key material.
             */
            
            memcpy(client_write_key,        key_material,           16);
            memcpy(server_write_key,        key_material+16,        16);
            memcpy(client_write_IV,         key_material+32,         4);
            memcpy(server_write_IV,         key_material+36,         4);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_AES_128_GCM(padding, length, data, NULL, client_write_key, client_write_IV);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_AES_128_GCM(padding, length, data, NULL, server_write_key, server_write_IV);
                
            }
            
        }
        
        case pcpp::SSL_SYM_AES_256_GCM:
        {
            
            /*
             * AES 256 has 256 bit keys, aka 32 byte
             */
            
            unsigned char client_write_key[32];
            unsigned char server_write_key[32];
            unsigned char client_write_IV[4];
            unsigned char server_write_IV[4];
            
            /*
             * Copy all bytes from the key material into our split key material.
             */
            
            memcpy(client_write_key,        key_material,           32);
            memcpy(server_write_key,        key_material+32,        32);
            memcpy(client_write_IV,         key_material+64,         4);
            memcpy(server_write_IV,         key_material+68,         4);
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                return Crypto::decrypt_AES_256_GCM(padding, length, data, NULL, client_write_key, client_write_IV);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                return Crypto::decrypt_AES_256_GCM(padding, length, data, NULL, server_write_key, server_write_IV);
                
            }
            
        }
        
        default:
            LOG_ERROR << "unsupported encryption found in ssl cipher suite: " << cipherSuite;
    }
    return Bytes();
}

//TODO: not abstract enough to handle all ciphers?
//TODO: check if the key material is accessible for all ciphers and protocols.
/*
 * AES GCM mode has 40 byte key material - we will see if it still works.
 * 
 */
pcapfs::Bytes pcapfs::SslFile::createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom, pcpp::SSLVersion sslVersion) {
    //TODO: for some cipher suites this is done by using hmac and sha256 (need to specify these!)
    /*
     * 
     * Problems will occur:
     * Different Hashes: SSLv3/TLS (most versions) differ, SSLv2 obviously too.
     * They do not use always SHA256! This will be a problem at some point
     * TLSv1.2 is the only one which uses this procedure *always* as far as I know.
     * 
     * 
     * TLS 1.0 Page 11, 12, 13
     * 
     *          PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
     *                                      P_SHA-1(S2, label + seed);
     * 
     * 
     * 
     * TLS 1.1 Page 13 and Page 14
     * 
     *          PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
     *                                      P _SHA-1(S2, label + seed);
     * 
     * 
     * TLS 1.2 
     * 
     * 
     *  1.2.  Major Differences from TLS 1.1
     * 
     *  This document is a revision of th*e TLS 1.1 [TLS1.1] protocol which
     *  contains improved flexibility, particularly for negotiation of
     *  cryptographic algorithms.  The major changes are:
     * 
     *  -   The MD5/SHA-1 combination in the pseudorandom function (PRF) has
     *      been replaced with cipher-suite-specified PRFs.  All cipher suites
     *      in this document use P_SHA256.
     * 
     * 
     * 
     *       PRF(secret, label, seed) = P_<hash>(secret, label + seed)
     * 
     *       key_block = PRF(SecurityParameters.master_secret,
     *                      " key expansion",                  
     *                      SecurityParameters.server_random +
     *                      SecurityParameters.client_random);
     * 
     * 
     * 
     * 
     * KEY MATERIAL (TLS 1.0/1.1/1.2):
     * 
     *          client_write_MAC_secret[SecurityParameters.hash_size]
     *          server_write_MAC_secret[SecurityParameters.hash_size]
     *          client_write_key[SecurityParameters.key_material_length]
     *          server_write_key[SecurityParameters.key_material_length]
     *          client_write_IV[SecurityParameters.IV_size]
     *          server_write_IV[SecurityParameters.IV_size]
     * 
     */
    
    switch(sslVersion) {
        case pcpp::SSLVersion::SSL2:
        {
            LOG_ERROR << "ssl2 is currently not supported\n";
            break;
        }
        case pcpp::SSLVersion::SSL3:
        {
            LOG_ERROR << "ssl3 is currently not supported\n";
            break;
        }
        case pcpp::SSLVersion::TLS1_0:
        {
            LOG_ERROR << "tls1 is currently not supported\n";
            break;
        }
        case pcpp::SSLVersion::TLS1_1:
        {
            LOG_ERROR << "tls1_1 is currently not supported\n";
            break;
        }
        case pcpp::SSLVersion::TLS1_2:
        {
            std::cout << "tls 1.2\n";
            break;
        }
        default:
            std::cout << "error\n";
    }
    
    
    /*
     * This is TLS 1.2
     * 
     * TODO: Build for ssl2,3,tls10,tls11
     * 
     */
    
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

    EVP_PKEY_CTX_free(pctx);
    
    return keyMaterial;
}


size_t pcapfs::SslFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: support to decrypt CBC etc. stuff... Maybe decrypt all of the data or return parts? Depends on mode of operation
    //TODO: split read into readStreamcipher, readCFB, readCBC...
    size_t fragment = 0;
    size_t posInFragment = 0;
    size_t position = 0;
    int counter = 0;

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
        counter++;
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

                std::shared_ptr<SSLKeyFile> keyPtr = std::dynamic_pointer_cast<SSLKeyFile>(
                        idx.get({"sslkey", keyIDinIndex}));
                if (isClientMessage(keyForFragment.at(fragment))) {
                    LOG_DEBUG << "CLIENT CLIENT CLIENT ? " + counter << std::endl;
                    decrypted = decryptData(previousBytes[fragment],
                                            toDecrypt.size(),
                                            (char *) toDecrypt.data(),
                                            (char *) keyPtr->getKeyMaterial().data(),
                                            isClientMessage(keyForFragment.at(fragment)));
                    
                    //
                    // FIX AHEAD!
                    //
                    
                } else {
                    LOG_DEBUG << "ERROR ERROR ERROR ? " + counter << std::endl;
                    
                    
                    decrypted = decryptData(previousBytes[fragment],
                                            toDecrypt.size(),
                                            (char *) toDecrypt.data(),
                                            (char *) keyPtr->getKeyMaterial().data(),
                                            isClientMessage(keyForFragment.at(fragment)));
                    
                }
                if(toRead != decrypted.size()) {
                    LOG_ERROR << "[E] various errors ahead?" << std::endl;
                    LOG_DEBUG << "[E] decrypted data is null and should not be used right now? decrypted_size: " << decrypted.size() << " - toRead: " << toRead << std::endl;
                }
                LOG_DEBUG << "decrypted data is null and should not be used right now? decrypted_size: " << decrypted.size() << " - toRead: " << toRead << std::endl;
                memset(buf + (position - startOffset), 0, toRead);
                memcpy(buf + (position - startOffset), decrypted.data() + posInFragment, decrypted.size());
            } else {
                LOG_ERROR << "NO KEYS FOUND FOR " << counter << std::endl;
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
        
/*
 * 
 * archive << sslVersion; ??
 * 
 */
        
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
