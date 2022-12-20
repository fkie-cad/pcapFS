#include "ssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rc4.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>

#include <boost/shared_ptr.hpp>

#include <assert.h>
#include <unordered_set>

#include "../filefactory.h"
#include "../logging.h"

#include "../crypto/cipherTextElement.h"
#include "../crypto/plainTextElement.h"
#include "../crypto/decryptSymmetric.h"



std::string pcapfs::SslFile::toString() {
	/*
	 *  std::string cipherSuite;
        uint16_t sslVersion;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;
	 *
	 */

	std::string ret;
	ret.append("SslFile object content:\n");

	ret.append("ciphersuite: ");
	ret.append(cipherSuite);
    ret.append("\n");

	ret.append("sslVersion: ");
	pcpp::SSLVersion v = sslVersion;
	ret.append(v.toString());
	ret.append("\n");

	ret.append("registeredAtFactory: ");
	ret.append(std::to_string(registeredAtFactory));
	ret.append("\n");

	ret.append("keyIDinIndex: ");
	ret.append(std::to_string(keyIDinIndex));
	ret.append("\n");


	ret.append("previousBytes: ");
	std::string prev_bytes;

	for(size_t i=0; i<previousBytes.size(); i++) {
		prev_bytes.append(std::to_string(previousBytes.at(i)));
		prev_bytes.append(" ");
	}

	ret.append(prev_bytes);
	ret.append("\n");


	ret.append("keyForFragment: ");
	std::string keys;

	for(size_t i=0; i<keyForFragment.size(); i++) {
		keys.append(std::to_string(keyForFragment.at(i)));
		keys.append(" ");
	}

	ret.append(keys);
	ret.append("\n");

	return ret;
}


size_t pcapfs::SslFile::calculateProcessedSize(const Index &idx) {

	size_t plaintext_size = read_for_plaintext_size(idx);
	return plaintext_size;
}


bool pcapfs::SslFile::isTLSTraffic(const FilePtr &filePtr) {
	//Step 1: detect ssl stream by checking for dst Port 443
	//TODO: other detection method -> config file vs heuristic?
	if (filePtr->getProperty("dstPort") == "443") {
		return true;
	}
	return false;
}


void pcapfs::SslFile::processTLSHandshake(bool &processedSSLHandshake,
		const bool clientMessage, const bool clientChangeCipherSpec,
		const bool serverChangeCipherSpec, pcpp::SSLHandshakeLayer *handshakeLayer,
		Bytes &clientRandom, uint64_t &offsetInLogicalFragment,
		Bytes &serverRandom, std::string &cipherSuite,
		pcpp::SSLVersion &sslVersion, pcpp::SSLLayer *sslLayer,
		uint64_t &clientEncryptedData, uint64_t &serverEncryptedData, bool &encryptThenMac) {
    
    size_t messageLength = 0;
    uint64_t numHandshakeMessages = handshakeLayer->getHandshakeMessagesCount();
    LOG_DEBUG << "numHandshakeMessages: " << numHandshakeMessages;
    if (numHandshakeMessages > 0){
        // add length of ssl record header
        offsetInLogicalFragment += 5;
    }

	for (uint64_t j = 0; j < numHandshakeMessages; ++j) {
		pcpp::SSLHandshakeMessage *handshakeMessage = handshakeLayer->getHandshakeMessageAt(j);
        messageLength = handshakeMessage->getMessageLength();
		pcpp::SSLHandshakeType handshakeType = handshakeMessage->getHandshakeType();

		if (handshakeType == pcpp::SSL_CLIENT_HELLO) {
			pcpp::SSLClientHelloMessage *clientHelloMessage =
					dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMessage);
			memcpy(clientRandom.data(),
					clientHelloMessage->getClientHelloHeader()->random,
					CLIENT_RANDOM_SIZE);
			//offsetInLogicalFragment += clientHelloMessage->getMessageLength();
            offsetInLogicalFragment += messageLength;
            LOG_DEBUG << "found client hello message";

		} else if (handshakeType == pcpp::SSL_SERVER_HELLO) {

            //Segfault in getCipherSuite() possible, encrypted handshake message can be mistakenly classified as Server Hello 
            // => when we had a server hello before, just continue
            if(processedSSLHandshake) {
                offsetInLogicalFragment += sslLayer->getHeaderLen() - 5;
                LOG_DEBUG << "found second server hello or wrong classification -> skip";
                continue;
            }

            pcpp::SSLServerHelloMessage *serverHelloMessage =
					dynamic_cast<pcpp::SSLServerHelloMessage*>(handshakeMessage);

            //offsetInLogicalFragment += serverHelloMessage->getMessageLength();
            offsetInLogicalFragment += messageLength;
            LOG_DEBUG << "found server hello message";
            memcpy(serverRandom.data(),
					serverHelloMessage->getServerHelloHeader()->random,
					SERVER_RANDOM_SIZE);
			
            //LOG_DEBUG << "chosen cipher suite: "
			//		<< serverHelloMessage->getCipherSuite()->asString();
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
			/*
			 * TLS Extension for HMAC truncation activated? Eventually then HMAC is always 10 bytes only.
			 */
			LOG_TRACE << "We have " << serverHelloMessage->getExtensionCount() << " extensions!";
			if (serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_TRUNCATED_HMAC) != NULL) {
				LOG_INFO << "Truncated HMAC extension was enabled!";
				throw "unsupported extension SSL_EXT_TRUNCATED_HMAC was detected!";
			}
			if (serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_ENCRYPT_THEN_MAC) != NULL) {
				LOG_INFO << "Encrypt-Then-Mac Extension IS ENABLED!";
                encryptThenMac = true;
			} else {
				LOG_INFO << "Encrypt-Then-Mac Extension IS NOT ENABLED";
			}

		} else if (handshakeType == pcpp::SSL_HANDSHAKE_UNKNOWN ||
                    (handshakeType == 0 && (clientChangeCipherSpec || serverChangeCipherSpec))) {
			//certificate status or encrypted handshake message

            // when the encrypted handshake message start with leading zeros, it may get interpreted as
            // multiple handshake messages of type 0 (Hello Request). Since we only want the correct offset,
            // we aquiesce in that and just add the message length. In the end, this still results in the correct offset.

            offsetInLogicalFragment += messageLength;

			if (clientMessage && clientChangeCipherSpec) {
                clientEncryptedData += messageLength;
				LOG_DEBUG
				<< "encrypted handshake message, client encrypted " << std::to_string(clientEncryptedData);
			} else if (serverChangeCipherSpec) {
                serverEncryptedData += messageLength;
				LOG_DEBUG
				<< "encrypted handshake message, server encrypted " << std::to_string(serverEncryptedData);
			}

		} else {
            offsetInLogicalFragment += messageLength;
            LOG_DEBUG << "handshake message type: " << handshakeMessage->getHandshakeType();
            LOG_DEBUG << "handshake message length: " << messageLength;
        }
	}
}


void pcapfs::SslFile::resultPtrInit(bool processedSSLHandshake,
		pcpp::SSLVersion sslVersion, const std::shared_ptr<SslFile> &resultPtr,
		const FilePtr &filePtr, const std::string &cipherSuite, const TimePoint timestamp,
		const Bytes &clientRandom, Index &idx, const Bytes &serverRandom, const bool encryptThenMac) {
	//search for master secret in candidates
	
    if (processedSSLHandshake) {
		Bytes masterSecret = searchCorrectMasterSecret(clientRandom, idx);
		if (!masterSecret.empty()) {
			Bytes keyMaterial = createKeyMaterial(masterSecret, clientRandom, serverRandom, sslVersion.asUInt());
            if(!keyMaterial.empty()) {
			    //TODO: not good to add sslkey file directly into index!!!
			    std::shared_ptr<SSLKeyFile> keyPtr = SSLKeyFile::createKeyFile(
			    		keyMaterial);
			    idx.insert(keyPtr);
			    resultPtr->setKeyIDinIndex(keyPtr->getIdInIndex());
			    resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);
            } else
                LOG_ERROR << "Failed to create key material. Look above why" << std::endl;
		}
	}
	
	resultPtr->setOffsetType(filePtr->getFiletype());
	resultPtr->setFiletype("ssl");
	resultPtr->setCipherSuite(cipherSuite);
    resultPtr->encryptThenMacEnabled = encryptThenMac;
	resultPtr->setSslVersion(sslVersion.asUInt());
	resultPtr->setFilename("SSL");
	resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
	resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
	resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
	resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
	resultPtr->setProperty("protocol", "ssl");
	resultPtr->setTimestamp(timestamp);
    
	if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
		resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
	}
}


std::vector<pcapfs::FilePtr> pcapfs::SslFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    //Step 1: detect ssl stream by checking for dst Port 443
    if(!isTLSTraffic(filePtr)) {
        return resultVector;
    }

    //Step 2: Get key material for SSL stream
    size_t size = 0;
    size_t numElements = filePtr->connectionBreaks.size();
    bool processedSSLHandshake = false;
    bool visitedVirtualSslFile = false;
    pcpp::Packet *packet = nullptr;

    Bytes clientRandom(CLIENT_RANDOM_SIZE);
    Bytes serverRandom(SERVER_RANDOM_SIZE);
    Bytes masterSecret;
    uint64_t clientEncryptedData = 0;
    uint64_t serverEncryptedData = 0;
    std::string cipherSuite = "";
    bool encryptThenMac = false;
    pcpp::SSLVersion sslVersion = pcpp::SSLVersion::SSL2; // init with a predefined value.
    bool clientChangeCipherSpec = false;
    bool serverChangeCipherSpec = false;

    std::shared_ptr<SslFile> resultPtr = nullptr;

    //Step 3: process all logical breaks in underlying virtual file
    //TODO: How many files? One?
    for (unsigned int i = 0; i < numElements; ++i) {
        LOG_DEBUG << "processing element " << std::to_string(i+1) << " of " << std::to_string(numElements);
        uint64_t &offset = filePtr->connectionBreaks.at(i).first;

        // get correct size (depending on element processed)
        // get size between the two connections
        if (i == numElements - 1) {
            size = filePtr->getFilesizeRaw() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        //connection break has wrong size if content is encrypted
        LOG_DEBUG << "connectionBreaks Size: " << size;


        //Step 4: one logical fragment may contain multiple ssl layer messages
        pcpp::SSLLayer *sslLayer = sslLayer->createSSLMessage((uint8_t *) data.data() + offset, size, nullptr, packet);
        uint64_t offsetInLogicalFragment = 0;
        bool connectionBreakOccured = true;

        while (sslLayer != nullptr) {
            pcpp::SSLRecordType recType = sslLayer->getRecordType();

            //Step 5: parse the corresponding ssl message
            if (recType == pcpp::SSL_HANDSHAKE) {
                pcpp::SSLHandshakeLayer *handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(sslLayer);

				processTLSHandshake(processedSSLHandshake, isClientMessage(i), clientChangeCipherSpec,
                        serverChangeCipherSpec, handshakeLayer, clientRandom,
						offsetInLogicalFragment, serverRandom, cipherSuite,
						sslVersion, sslLayer, clientEncryptedData,
						serverEncryptedData, encryptThenMac);

                // assert(offsetInLogicalFragment == size)

            } else if (recType == pcpp::SSL_CHANGE_CIPHER_SPEC) {
                if (isClientMessage(i)) {
                    LOG_DEBUG << "client starting encryption now!";
                    clientChangeCipherSpec = true;
                } else {
                    LOG_DEBUG << "server starting encryption now!";
                    serverChangeCipherSpec = true;
                }

                //pcpp::SSLChangeCipherSpecLayer *changeCipherSpecLayer =
                //        dynamic_cast<pcpp::SSLChangeCipherSpecLayer*>(sslLayer);
                //offsetInLogicalFragment += (changeCipherSpecLayer->getDataLen() +
                //                            changeCipherSpecLayer->getHeaderLen());
                //LOG_DEBUG << "getDataLen():" << changeCipherSpecLayer->getDataLen();
                //LOG_DEBUG << "getHeaderLen():" << changeCipherSpecLayer->getHeaderLen();

                // length of change cipher spec is always 1, add ssl record layer header length
                offsetInLogicalFragment += 6;


            } else if (recType == pcpp::SSL_APPLICATION_DATA) {

                pcpp::SSLApplicationDataLayer *applicationDataLayer =
                        dynamic_cast<pcpp::SSLApplicationDataLayer *>(sslLayer);

                uint64_t encryptedDataLen = applicationDataLayer->getEncryptedDataLen();
                uint64_t completeSSLLen = applicationDataLayer->getHeaderLen();

                LOG_TRACE << "applicationDataLayer->getEncryptedDataLen(): " << applicationDataLayer->getEncryptedDataLen();
                LOG_TRACE << "applicationDataLayer->getHeaderLen(): " << applicationDataLayer->getHeaderLen();

                uint64_t bytesBeforeEncryptedData = completeSSLLen - encryptedDataLen;
                LOG_TRACE << "bytesBeforeEncryptedData: " << bytesBeforeEncryptedData;

                //create ssl application file
                //TODO: does client always send first?
                if (resultPtr == nullptr) {
                    resultPtr = std::make_shared<SslFile>();

                    //search for master secret in candidates
					resultPtrInit(processedSSLHandshake,
							sslVersion, resultPtr, filePtr, cipherSuite, filePtr->connectionBreaks.at(i).second,
							clientRandom, idx, serverRandom, encryptThenMac);
                    
                    //TODO
                    //init with 0, unsure where we init this right now
                    resultPtr->filesizeProcessed = 0;
                    resultPtr->filesizeRaw = 0;
                }

                /*
                 * We need to distinguish between 2 cases:
                 * 
                 * A) We have a Key and we do the decryption with this key
                 * B) We do not have the key and only return the ciphertext.
                 * 
                 * We got this information from the initialization step from resultPtrInit.
                 */
                
                if (resultPtr->flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                    LOG_INFO << "[PARSING TLS APP DATA **WITH** KEY]"; 
                    resultPtr->flags.set(flags::PROCESSED);
                } else {
                    LOG_INFO << "[PARSING TLS APP DATA **WITHOUT** KEY]"; 
                }
                
                if (connectionBreakOccured) {
                    /*
                     * Prevent the run of the calculation stub in the first execution of the loop, there is no data ready.
                     */
                    if(resultPtr->filesizeRaw > 0) {
                        size_t calculated_size = resultPtr->calculateProcessedSize(idx);
                        resultPtr->setFilesizeProcessed(resultPtr->filesizeProcessed + calculated_size);
                        visitedVirtualSslFile = true;
                    }
                    
                    resultPtr->connectionBreaks.push_back({resultPtr->getFilesizeProcessed(), filePtr->connectionBreaks.at(i).second});
                    LOG_TRACE << "file size processed for this virtual file: " 
                    << resultPtr->getFilesizeProcessed()
                    << " and current break: " 
                    << resultPtr->getFilesizeProcessed();
                    connectionBreakOccured = false;
                }
                
                //each application data is part of the stream
                Fragment fragment;
                fragment.id = filePtr->getIdInIndex();
                fragment.start = offset + bytesBeforeEncryptedData + offsetInLogicalFragment;
                
                LOG_TRACE << "[FRAGMENT.START: " << offset << " + " <<  bytesBeforeEncryptedData << " + " << offsetInLogicalFragment << "]: " << fragment.start;
                
                fragment.length = encryptedDataLen;
                
                // if size is a mismatch => ssl packet is malformed
                // TODO: Better detection of malformed ssl packets
                if (fragment.length > sslLayer->getDataLen()) {
                    break;
                }
                
                resultPtr->fragments.push_back(fragment);
                
                LOG_DEBUG << "found app data";
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
                
                resultPtr->setFilesizeRaw(resultPtr->getFilesizeRaw() + encryptedDataLen);
				
				LOG_DEBUG << "Full SSL File afterwards:\n" << resultPtr->toString();
			}
			
            LOG_DEBUG << "OFFSET IN LOG FRAGMENT: " << std::to_string(offsetInLogicalFragment);
            sslLayer->parseNextLayer();
            sslLayer = dynamic_cast<pcpp::SSLLayer *>(sslLayer->getNextLayer());
            
            /*
             * If this is our last iteration we update the filesizeProcessed again
             * TODO: make this last step the only step to reduce duplicate decryption.
             * Idea: Just one decryption after all ciphertext is available. We need to keep track
             * of all connection breaks and package breaks. Then we can reconstruct it here inside the parser.
             */
            if(sslLayer == nullptr && visitedVirtualSslFile == true && resultPtr->flags.test(flags::PROCESSED)) {
                LOG_DEBUG << "Fixing the fileSizeProcessed, setting it to the full size of plaintext.";
                size_t calculated_size = resultPtr->calculateProcessedSize(idx);
                /*
                 * calculated_size contains all plain text in this context, therefore we do not need to add the current filesizeProcessed.
                 */
                resultPtr->setFilesizeProcessed(calculated_size);
            }
        }
    }

    //TODO: multiple ssl streams in one tcp stream?!
    if (resultPtr != nullptr) {
        resultVector.push_back(resultPtr);
    }

    return resultVector;
}

//Returns the correct Master Secret out of a bunch of candidates
pcapfs::Bytes pcapfs::SslFile::searchCorrectMasterSecret(const Bytes &clientRandom, const Index &idx) {

    std::vector<pcapfs::FilePtr> keyFiles = idx.getCandidatesOfType("sslkey");

    for (auto &keyFile: keyFiles) {
        std::shared_ptr<SSLKeyFile> sslKeyFile = std::dynamic_pointer_cast<SSLKeyFile>(keyFile);

        if(sslKeyFile->getClientRandom() == clientRandom){
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




//TODO: not abstract enough to handle all ciphers?
//TODO: check if the key material is accessible for all ciphers and protocols.
/*
 * AES GCM mode has 40 byte key material - we will see if it still works.
 * 
 */



int pcapfs::SslFile::decryptData(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output) {
	pcpp::SSLCipherSuite *cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByName(getCipherSuite());

    if(cipherSuite == NULL){
        LOG_ERROR << "decryption failed: unsupported cipher suite " << getCipherSuite();
        return 1;
    }

    // TODO: make those checks earlier
    if(cipherSuite->getKeyExchangeAlg() != pcpp::SSLKeyExchangeAlgorithm::SSL_KEYX_RSA) {
        LOG_ERROR << "decryption failed: only RSA key exchange is supported";
        return 1;
    }

    switch (cipherSuite->getSymKeyAlg()) {
        
        /*
         * TODO: maybe redesign since some ciphers need different call to PRF:
         * 
         * AES GCM:
         * keys = PRF(master_secret, "key expansion", server_random + client_random, 40)
         * 
         * and the PRF might even differ (SHA256 vs SHA384):
         * https://tools.ietf.org/html/rfc5246#section-5
         */
        
        case pcpp::SSL_SYM_RC4_128:
        {
            Crypto::decrypt_RC4_128(input, output, cipherSuite->getMACAlg());
            break;
        }
        
        case pcpp::SSL_SYM_AES_128_CBC:
        {
            Crypto::decrypt_AES_CBC(input, output, cipherSuite->getMACAlg(), 16);
            break;
        }

        case pcpp::SSL_SYM_AES_256_CBC:
        {
            Crypto::decrypt_AES_CBC(input, output, cipherSuite->getMACAlg(), 32);
            break;
        }
        
        /*case pcpp::SSL_SYM_AES_128_GCM:
        {
            Crypto::decrypt_AES_128_GCM(input, output);
            break;
        }*/
        
        default:
            LOG_ERROR << "unsupported encryption found in ssl cipher suite: " << cipherSuite->asString();
            return 1;
    }
    return 0;
}



pcapfs::Bytes pcapfs::SslFile::createKeyMaterial(const Bytes &masterSecret, const Bytes &clientRandom, const Bytes &serverRandom, uint16_t sslVersion) {
    //TODO: for some cipher suites this is done by using hmac and sha256 (need to specify these!)
    /*
     * 
     * Problems will occur:
     * Different Hashes: SSLv3/TLS (most versions) differ, SSLv2 obviously too.
     * They do not use always SHA256! This will be a problem at some point
     * TLSv1.2 is the only one which uses this procedure *always* as far as I know.
     * 
     * 
     * SSLv3:
     * 
     * It is a bit longer, see this one:
     * 
     * https://tools.ietf.org/html/rfc6101#section-6.2.1
     * 
     * 
     * TLS 1.0 and TLS 1.1:
     *          PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
     *                                      P_SHA-1(S2, label + seed);
     * 
     * TLS 1.2 :
     *      "The MD5/SHA-1 combination in the pseudorandom function (PRF) has
     *      been replaced with cipher-suite-specified PRFs.  All cipher suites
     *      in this document use P_SHA256.""
     * 
     *       PRF(secret, label, seed) = P_SHA256(secret, label + seed)
     * 
     * 
     * 
     * key_block = PRF(SecurityParameters.master_secret,
     *                 "key expansion",                  
     *                 SecurityParameters.server_random +
     *                 SecurityParameters.client_random);
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
     * The concrete openssl doc for this section:
     * 
     * https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_CTX_set_tls1_prf_md.html
     * https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_derive.html
     */
    
    Bytes keyMaterial(0);

    if((sslVersion == pcpp::SSLVersion::TLS1_0) || (sslVersion == pcpp::SSLVersion::TLS1_1) ||
        (sslVersion == pcpp::SSLVersion::TLS1_2)) {

        // current max key material size for AES256 with SHA384: 2*48 + 2*32 + 2*16 Byte
        size_t KEY_MATERIAL_SIZE = 192;
        size_t const LABEL_SIZE = 13;
        char const LABEL[14] = "key expansion";
        size_t const seedSize = LABEL_SIZE + SERVER_RANDOM_SIZE + CLIENT_RANDOM_SIZE;
        Bytes seed(seedSize);
        memcpy(&seed[0], LABEL, LABEL_SIZE);
        memcpy(&seed[LABEL_SIZE], serverRandom.data(), SERVER_RANDOM_SIZE);
        memcpy(&seed[LABEL_SIZE + SERVER_RANDOM_SIZE], clientRandom.data(), CLIENT_RANDOM_SIZE);
        
        unsigned char error = 0;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
        if(!pctx) {
            LOG_ERROR << "Openssl: Failed to allocate public key algorithm context" << std::endl;
            error = 1;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            LOG_ERROR << "Openssl: Failed to initialize public key algorithm context" << std::endl;
            error = 1;
        }

        if(sslVersion == pcpp::SSLVersion::TLS1_2) {
            if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
                LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.2" << std::endl;
                error = 1;
            }
        } else if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0) {
            LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.0 or 1.1" << std::endl;
            error = 1;
        }

        if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, masterSecret.data(), 48) <= 0) {
        	LOG_ERROR << "Openssl: PRF key derivation failed" << std::endl;
            error = 1;
        }
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seedSize) <= 0) {
        	LOG_ERROR << "Openssl: Failed to set the seed" << std::endl;
            error = 1;
        }

        keyMaterial.resize(KEY_MATERIAL_SIZE);
        if (EVP_PKEY_derive(pctx, keyMaterial.data(), &KEY_MATERIAL_SIZE) <= 0) {
        	LOG_ERROR << "Openssl: Failed to derive the shared secret" << std::endl;
            error = 1;
        }

        if(error) {
            ERR_print_errors_fp(stderr);  
            keyMaterial.clear();
        }

        EVP_PKEY_CTX_free(pctx);

    } else {
        pcpp::SSLVersion version(sslVersion);
        LOG_ERROR << "TLS/SSL version not supported, we detected the ssl version code: " << version.toString() << std::endl;
    }

    return keyMaterial;
}


/*
 * TODO: 
 * 
 * CURRENT READ FUNCTION:
 * 
 * The current read function currently tries to encrypt traffic at a certain position.
 * We wanted to implement an abstract way to ask for decrypted data at a certain position
 * WITHOUT decrypting everything every time.
 * 
 * This seems not to be possible at this point.
 * 
 * Idea: We need a mapping which does the following:
 * 
 * +----------+----------+----------
 * |          |          |
 * |   AAAA   |   BBBB   |   ...
 * |          |          |
 * +----------+----------+----------
 * 
 * If someone asks now for block 2 (BBBB), then we should return such a structure:
 * 
 * +----------+----------+---------------
 * |          |          |
 * |   0000   |   BBBB   |   0000....
 * |          |          |
 * +----------+----------+---------------
 * 
 * Many ciphers require a complete decryption of such a track.
 * This leads to, depending on the length of the track, a very inefficient implementation.
 * 
 * But since this is required for many ciphers such as CBC or GCM cipher modes, we need to
 * decrypt a certain amount of blocks, either up to the requested block or other, etc.
 * This is a topic highly depending on the cipher and the cipher mode used in the TLS application data.
 * 
 * Improvement goals:
 * 
 * ### Build a function which decrypts all of the blocks from the beginning.
 * ### Build a handler function which wraps the plaintext to text for the user, meaning: "remove" the MAC.
 * ### Build a wrapper which handles specific requests to single blocks in the chain (using certain offsets).
 * 
 * 
 * 
 * CHALLENGES:
 * 
 * ### plaintext offset calculation depends i.e. on the size of the authentication digests, we need another abstraction layer:
 * 
 * 
 * ciphertext (symbolic AAAA and BBBB, think about garbage looking bytes):
 * +----------+----------+----------
 * |          |          |
 * |   AAAA   |   BBBB   |   ...
 * |          |          |
 * +----------+----------+----------
 * 
 * 
 * plaintext (derived from decryption, has a lot of stuff like message authentication digests):
 * +----------+----------+----------
 * |      | M |      | M |
 * |   AA | A |   BB | A |   ...
 * |      | C |      | C |
 * +----------+----------+----------
 * 
 * 
 * real text, readable by the user, either MAC checked or not:
 * +----------+----------+----------
 * |          |          |
 * |   abcd   |   efgh   |   ...
 * |          |          |
 * +----------+----------+----------
 * 
 * Concrete: If the user requests the block 2 containing the BBBB ciphertext, we want to provide efgh to the user.
 * We still have to decrypt the complete TLS application data stream.
 * 
 * 
 * 
 * FUTURE GOALS:
 * 
 * ### Cache the decrypted streams to prevent the decryption of the complete stream in requests which loop through
 *     all fields of a stream, refer inside a single stream or many recurring requests to a certain pool of
 *     TLS application data streams.
 * 
 * 
 * 
 * 
 */

size_t pcapfs::SslFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    
    if(flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
		
        LOG_TRACE << "[USING KEY] start with reading decrypted content, startOffset: " << startOffset << " and length: " << length;
        
        // Here, length is the plaintext length!
		
        return read_decrypted_content(startOffset, length, idx, buf);
        
	} else {
        
		LOG_TRACE << "[NO KEY] start with reading raw, startOffset: " << startOffset << " and length: " << length;
        
        // Here, length is the ciphertext length!
        
		return read_raw(startOffset, length, idx, buf);
        
	}
}



size_t pcapfs::SslFile::read_raw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: right now this assumes each http file only contains ONE offset into a tcp stream
	LOG_TRACE << "read_raw offset size: " << fragments.size();
    size_t position = 0;
    size_t posInFragment = 0;
    size_t fragment = 0;
    
    while (position < startOffset) {
        position += fragments[fragment].length;
        fragment++;
    }
    
    if (position > startOffset) {
        fragment--;
        posInFragment = fragments[fragment].length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }
        
    while (position < startOffset + length && fragment < fragments.size()) {
        size_t toRead = std::min(fragments[fragment].length - posInFragment, length - (position - startOffset));
        
        pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
        filePtr->read(fragments[fragment].start + posInFragment, toRead, idx, buf + (position - startOffset));
        
        // set run variables in case next fragment is needed
        position += toRead;
        fragment++;
        posInFragment = 0;
    }
    
    
    if (startOffset + length < filesizeRaw) {
        //read till length is ended
        LOG_TRACE << "File is not done yet. (filesizeRaw: " << filesizeRaw << ")";
        LOG_TRACE << "Length read: " << length;
        return length;
    } else {
        // read till file end
        LOG_TRACE << "File is done now. (filesizeRaw: " << filesizeRaw << ")";
        LOG_TRACE << "all processed bytes: " << filesizeRaw - startOffset;
        return filesizeRaw - startOffset;
    }
}

size_t pcapfs::SslFile::read_decrypted_content(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    size_t position = 0;
    size_t posInFragment = 0;
    size_t fragment = 0;

    std::vector< std::shared_ptr<CipherTextElement>> cipherTextVector(0);
    std::vector< std::shared_ptr<PlainTextElement>> plainTextVector(0);

    int offset = 0;
    std::vector<Bytes> result;
    Bytes write_me_to_file;
    bool buffer_needs_content = true;
    
    // kind of a hack, null bytes should work but are kind of a special case.
    // if all bytes are == 0, the result is true and the buffer "empty".
    // (.empty() does not worked as it is resized before)
    for (auto &elem: buffer) {
        if (elem != 0) {
            buffer_needs_content = false;
        }
    }
    
    if(buffer_needs_content == false) {
        
        LOG_DEBUG << "[BUFFER HIT] buffer is this:" << std::endl;
        std::string s(buffer.begin(), buffer.end());
        // LOG_ERROR << s;
        //_Exit(0);
        
        assert(buffer.size() == filesizeProcessed);
        
        // BIO_dump_fp (stdout, (const char *) buffer.data(), buffer.size());
        
        memcpy(buf, (const char*) buffer.data() + startOffset, length);
        
        if (startOffset + length < filesizeProcessed) {
            //read till length is ended
            LOG_TRACE << "File is not done yet. (filesizeProcessed: " << filesizeProcessed << ")";
            LOG_TRACE << "Length read: " << length;
            return length;
        } else {
            // read till file end
            LOG_TRACE << "File is done now. (filesizeProcessed: " << filesizeProcessed << ")";
            LOG_TRACE << "all processed bytes: " << filesizeProcessed - startOffset;
            return filesizeProcessed - startOffset;
        }
        
    }
    
    if(buffer.empty() || buffer_needs_content) {

        getFullCipherText(idx, cipherTextVector);

        /*for(size_t i=0; i< cipherTextVector.size(); i++) {
            CipherTextElement *elem = cipherTextVector.at(i).get();
            elem->printMe();
        }*/

        decryptCiphertextVecToPlaintextVec(cipherTextVector, plainTextVector);


        for(size_t i=0; i<plainTextVector.size(); i++) {
            PlainTextElement *elem = plainTextVector.at(i).get();
            //elem->printMe();
            result.push_back(elem->getPlaintextBlock());
            write_me_to_file.insert(std::end(write_me_to_file), std::begin(result.at(i)), std::end(result.at(i)) );
            offset += elem->getPlaintextBlock().size();
        }
    }
	
    while (position < startOffset) {
        position += result[fragment].size();
        fragment++;
    }

    if (position > startOffset) {
        fragment--;
        posInFragment = result[fragment].size() - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    /*
     * Now we have the position in the result vector: posInFragment,
     * the concrete fragment itself (fragment, element of result where we begin our decrypted plaintext stream)
     * and the offset in the fragment (position).
     * We copy at the begin of the position the relevant bytes into the target buffer.
     * The data stream is copied until we reach the length or all data is copied.
     */
    
    
    bool first_iteration = true;
    Bytes bytes_ref;
    
    
    if(length > write_me_to_file.size()) {
        LOG_ERROR << "The requested file is larger than the decrypted resource. Diff: " << length - write_me_to_file.size();
    }
    
    size_t byte_counter = 0;
    
    
    while(position < startOffset + length && fragment < result.size())  {
        // minimum handles 2 cases here: 
        // either we have a "default" case, or we have a special case aka the beginning or end of a fragment.
        size_t toRead = std::min(result[fragment].size() - posInFragment, length - (position - startOffset));
        if(first_iteration) {
            bytes_ref = result[fragment];
            bytes_ref.erase(bytes_ref.begin(), bytes_ref.begin() + posInFragment);
            first_iteration = false;
        } else {
            bytes_ref = result[fragment];
        }
        memcpy(buf + (position - startOffset), (const char*) bytes_ref.data(), toRead);
        byte_counter += toRead;
        fragment++;
        posInFragment = 0;
        LOG_DEBUG << "bytes_ref.size(): " << bytes_ref.size() << " " << "toRead: " << toRead;
        position += bytes_ref.size();
    }
    
    if(length > write_me_to_file.size()) {
        LOG_ERROR << "The requested file is larger than the decrypted resource. Diff: " << length - write_me_to_file.size() << "byte_counter: " << byte_counter;
    }
    
    /*
	if (write_me_to_file.size() > 0) {

		LOG_ERROR << "offset: " << offset << " startOffset: " << startOffset <<
				" length: " << length << " result_size: " << write_me_to_file.size();

		memset(buf + startOffset, 0, length);
		
        //This produces a crash when write_me_to_file is large enough.

         memcpy(buf, (const char*) write_me_to_file.data() + startOffset, length);

		LOG_ERROR << "offset: " << offset << " startOffset: " << startOffset <<
				" length: " << length << " result_size: " << write_me_to_file.size();
	} else {
		LOG_ERROR << "Empty buffer after decryption, probably unwanted behavior.";
	}
	*/
	
    
	/*
	if (startOffset + length < filesizeRaw) {
		//read till length is ended
		LOG_TRACE << "File is not done yet. (filesizeraw: " << filesizeRaw << ")";
		LOG_TRACE << "Length read: " << length;
		return length;
	} else {
		// read till file end
		LOG_TRACE << "File is done now. (filesizeraw: " << filesizeRaw << ")";
		LOG_TRACE << "all processed bytes: " << filesizeRaw - startOffset;
		return filesizeRaw - startOffset;
	}
	*/
	if (startOffset + length < filesizeProcessed) {
		//read till length is ended
		LOG_TRACE << "File is not done yet. (filesizeProcessed: " << filesizeProcessed << ")";
		LOG_TRACE << "Length read: " << length;
		return length;
	} else {
		// read till file end
		LOG_TRACE << "File is done now. (filesizeProcessed: " << filesizeProcessed << ")";
		LOG_TRACE << "all processed bytes: " << filesizeProcessed - startOffset;
		return filesizeProcessed - startOffset;
	}
}






/*
 * This is the new function for the calculation of the plaintext:
 * Better: return a vector of std::pair of ciphertext length and
 * the respective plaintext length. Then you need only one decryption.
 */
size_t pcapfs::SslFile::read_for_plaintext_size(const Index &idx) {
    std::vector< std::shared_ptr<CipherTextElement>> cipherTextVector(0);
    std::vector< std::shared_ptr<PlainTextElement>> plainTextVector(0);
    
    getFullCipherText(idx, cipherTextVector);
    
    /*for(size_t i=0; i< cipherTextVector.size(); i++) {
        CipherTextElement *elem = cipherTextVector.at(i).get();
        elem->printMe();
    }*/
    
    decryptCiphertextVecToPlaintextVec(cipherTextVector, plainTextVector);
    
    size_t offset = 0;
    LOG_TRACE << "entering file writer..." << std::endl;
    std::vector<Bytes> result;

    for(size_t i=0; i<plainTextVector.size(); i++) {
        PlainTextElement *elem = plainTextVector.at(i).get();
        //elem->printMe();
        result.push_back(elem->getPlaintextBlock());
        offset += elem->getPlaintextBlock().size();
    }
    
    LOG_TRACE << "offset size (this is the value we want to use later): " << offset;
    return offset;
}



/*
 * pcapfs::SslFile::getFullCipherText
 * 
 * The function gets the full TLS application layer stream into a vector.
 * Each element in the vector represents one decrypted packet, containing a alternating stream of the packets from client and server.
 * Concrete: iterate over all fragments, return the cipher text blocks and the keymaterial.
 * 
 * TODO: New datatype for the vector, a datatype holding:
 *          - pcapfs::Bytes object
 *          - key material bytes
 *          - cipher type, ssl version, server or client (?)
 * 
 * After use of this function, free every pointer in outputCipherTextVector at the function which called 'getFullCipherText'.
 * 
 */
size_t pcapfs::SslFile::getFullCipherText(const Index &idx, std::vector< std::shared_ptr<CipherTextElement>> &outputCipherTextVector) {
    size_t fragment = 0;
    size_t position = 0;
    int counter = 0;
    
    
    while (fragment < fragments.size()) {
                
        counter++;
        size_t toRead = fragments[fragment].length;
        
        //TODO: is start=0 really good for missing data?
        // -> missing data should probably be handled in an exception?
        
        if (fragments[fragment].start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            LOG_INFO << "We have some missing TCP data: pcapfs::flags::MISSING_DATA was set";
        } else {
            
            // Read the bytes from the packets of the file (using the file pointer):
            // After this step, toDecrypt is filled with bytes.
            
            // filePtr is a TCP file pointer at this position, the underlying file structure
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
            pcapfs::Bytes toDecrypt(this->fragments.at(fragment).length);
            filePtr->read(fragments.at(fragment).start, fragments.at(fragment).length, idx, (char *) toDecrypt.data());
            
            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                
                std::shared_ptr<SSLKeyFile> keyPtr = std::dynamic_pointer_cast<SSLKeyFile>(
                    idx.get({"sslkey", getKeyIDinIndex()}));

                std::shared_ptr<CipherTextElement> cte = std::make_shared<CipherTextElement>();
                cte->setVirtualFileOffset(previousBytes[fragment]);
                cte->setCipherSuite(this->cipherSuite);
                cte->setSslVersion(this->sslVersion);
                cte->setCipherBlock(toDecrypt);
                cte->setLength(toRead);
                cte->setKeyMaterial(keyPtr->getKeyMaterial());
                cte->isClientBlock = isClientMessage(keyForFragment.at(fragment));
                cte->encryptThenMacEnabled = this->encryptThenMacEnabled;
                outputCipherTextVector.push_back(cte);
            } else {
                LOG_INFO << "NO KEYS FOUND FOR " << counter;
            }
        }
        
        // set run variables in case next fragment is needed
        position += toRead;
        fragment++;
    }
    
    
    // Assertion for checking if we really read everything from the buffer.
    // Constructed as assertion because only active in debug mode.
    assert(
        ([&]() -> bool{
            if(flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                size_t counter_for_bytes_output_ciphertext = 0;
                size_t counter_for_fragments = 0;
                for (auto &element: outputCipherTextVector) {
                    counter_for_bytes_output_ciphertext += element->getLength();
                }
                for (auto fragment: fragments) {
                    counter_for_fragments += fragment.length;
                }
                if (position == counter_for_bytes_output_ciphertext && position == counter_for_fragments) {
                    return true;
                } else {
                    LOG_ERROR << "+++ ASSERTION TRIGGERED +++";
                    LOG_ERROR << "position: " << position;
                    LOG_ERROR << "counter_for_bytes_output_ciphertext: " << counter_for_bytes_output_ciphertext;
                    LOG_ERROR << "counter_for_fragments: " << counter_for_fragments;
                    return false;
                }
            } else {
                // Always true if we do not have any keys.
                return true;
            }
        })()
    );
    
    
    
    // Filesize Raw is used, because we read the ciphertext aka the raw file.
    return filesizeRaw;
}


/*
 * pcapfs::SslFile::decryptCiphertextToPlaintext
 * 
 * Encrypt the vector of bytes using the key material provided via every frame of the vector.
 * returns a vector of plaintext plus information such as if mac, alignment, padding is correct.
 * This is the vector which can be used by a user to get the plaintext with full information via the next function prototype.
 * 
 */
void pcapfs::SslFile::decryptCiphertextVecToPlaintextVec(
		std::vector< std::shared_ptr<CipherTextElement>> &cipherTextVector,
		std::vector< std::shared_ptr<PlainTextElement>> &outputPlainTextVector
	) {


    for (size_t i=0; i<cipherTextVector.size(); i++) {
        std::shared_ptr<CipherTextElement> element = cipherTextVector.at(i);
        std::shared_ptr<PlainTextElement> output = std::make_shared<PlainTextElement>();

        if(decryptData(element, output))
            // decryption failed
            output->setPlaintextBlock(element->getCipherBlock());
        
        output->setVirtualFileOffset(element->getVirtualFileOffset());
        output->isClientBlock = element->isClientBlock;
        output->setCipherSuite(element->getCipherSuite());
        output->setSslVersion(element->getSslVersion());
        
        outputPlainTextVector.push_back(output);
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
    archive << sslVersion;
    archive << keyIDinIndex;
    archive << previousBytes;
    archive << keyForFragment;
}


void pcapfs::SslFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    archive >> cipherSuite;
    archive >> sslVersion;
    archive >> keyIDinIndex;
    archive >> previousBytes;
    archive >> keyForFragment;
}
