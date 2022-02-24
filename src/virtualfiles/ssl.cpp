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

#include "../filefactory.h"
#include "../logging.h"

#include "../crypto/cipherTextElement.h"
#include "../crypto/plainTextElement.h"
#include "../crypto/decryptSymmetric.h"

namespace {
    //TODO: variable size get them in static functions?
    size_t const CLIENT_RANDOM_SIZE = 32;
    size_t const SERVER_RANDOM_SIZE = 32;
    //MAC size may vary? AES_CBC should have 20 Bytes MAC 
    //size_t const MAC_SIZE = 16;
    //size_t const KEY_SIZE = 16;
}

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

	for(int i=0; i<previousBytes.size(); i++) {
		prev_bytes.append(std::to_string(previousBytes.at(i)));
		prev_bytes.append(" ");
	}

	ret.append(prev_bytes);
	ret.append("\n");


	ret.append("keyForFragment: ");
	std::string keys;

	for(int i=0; i<keyForFragment.size(); i++) {
		keys.append(std::to_string(keyForFragment.at(i)));
		keys.append(" ");
	}

	ret.append(keys);
	ret.append("\n");

	return ret;
}

//Constructor
pcapfs::SslFile::SslFile() {};

size_t pcapfs::SslFile::calculateProcessedSize(uint64_t length_of_ciphertext, Index &idx) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");

	size_t plaintext_size = read_for_size(0, length_of_ciphertext, idx);
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
	return plaintext_size;
}

bool pcapfs::SslFile::isTLSTraffic(const FilePtr &filePtr, bool tlsTrafficDetected) {
	//Step 1: detect ssl stream by checking for dst Port 443
	//TODO: other detection method -> config file vs heuristic?
	tlsTrafficDetected = false;
	if (filePtr->getProperty("dstPort") == "443") {
		tlsTrafficDetected = true;
	}
	return tlsTrafficDetected;
}

bool pcapfs::SslFile::processTLSHandshake(bool processedSSLHandshake,
		unsigned int i, bool clientChangeCipherSpec,
		bool serverChangeCipherSpec, pcpp::SSLHandshakeLayer *handshakeLayer,
		Bytes &clientRandom, uint64_t &offsetInLogicalFragment,
		Bytes &serverRandom, std::string &cipherSuite,
		pcpp::SSLVersion &sslVersion, pcpp::SSLLayer *sslLayer,
		uint64_t &clientEncryptedData, uint64_t &serverEncryptedData) {
	for (uint64_t j = 0; j < handshakeLayer->getHandshakeMessagesCount(); ++j) {
		pcpp::SSLHandshakeMessage *handshakeMessage =
				handshakeLayer->getHandshakeMessageAt(j);
		pcpp::SSLHandshakeType handshakeType =
				handshakeMessage->getHandshakeType();
		if (handshakeType == pcpp::SSL_CLIENT_HELLO) {
			pcpp::SSLClientHelloMessage *clientHelloMessage =
					dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMessage);
			memcpy(clientRandom.data(),
					clientHelloMessage->getClientHelloHeader()->random,
					CLIENT_RANDOM_SIZE);
			offsetInLogicalFragment += clientHelloMessage->getMessageLength();
		} else if (handshakeType == pcpp::SSL_SERVER_HELLO) {
			pcpp::SSLServerHelloMessage *serverHelloMessage =
					dynamic_cast<pcpp::SSLServerHelloMessage*>(handshakeMessage);
			memcpy(serverRandom.data(),
					serverHelloMessage->getServerHelloHeader()->random,
					SERVER_RANDOM_SIZE);
			offsetInLogicalFragment += serverHelloMessage->getMessageLength();
			
            LOG_DEBUG << "found server hello message";
			
            LOG_DEBUG << "chosen cipher suite: "
					<< serverHelloMessage->getCipherSuite()->asString();
			if (serverHelloMessage->getCipherSuite()) {
				/*
				 * Those values are used for the decryption in decryptData() function
				 */
				cipherSuite = serverHelloMessage->getCipherSuite()->asString();
				sslVersion = sslLayer->getRecordVersion();
			} else {
				cipherSuite = "UNKNOWN_CIPHER_SUITE";
				/*
				 * TODO: handle this exception properly
				 * 
				 */
				throw "unsupported cipher detected";
			}
			processedSSLHandshake = true;
			LOG_DEBUG
			<< "handshake completed";
			/*
			 * TLS Extension for HMAC truncation activated? Eventually then HMAC is always 10 bytes only.
			 */
			LOG_TRACE
			<< "We have " << serverHelloMessage->getExtensionCount()
					<< " extensions!";
			if (serverHelloMessage->getExtensionOfType(
					pcpp::SSL_EXT_TRUNCATED_HMAC) != NULL) {
				LOG_INFO
				<< "Truncated HMAC extension was enabled!";
				throw "unsupported extension SSL_EXT_TRUNCATED_HMAC was detected!";
			}
			if (serverHelloMessage->getExtensionOfType(
					pcpp::SSL_EXT_ENCRYPT_THEN_MAC) != NULL) {
				LOG_INFO
				<< "Encrypt-Then-Mac Extension IS ENABLED!";
			} else {
				LOG_INFO
				<< "Encrypt-Then-Mac Extension IS NOT ENABLED";
			}
		} else if (handshakeType == pcpp::SSL_CERTIFICATE) {
			pcpp::SSLCertificateMessage *certificateMessage =
					dynamic_cast<pcpp::SSLCertificateMessage*>(handshakeMessage);
			offsetInLogicalFragment += certificateMessage->getMessageLength();
			//TODO: sslcert as a virtual file
			LOG_DEBUG
			<< "found certificiate!";
		} else if (handshakeType == pcpp::SSL_SERVER_DONE) {
			pcpp::SSLServerHelloDoneMessage *serverHelloDoneMessage =
					dynamic_cast<pcpp::SSLServerHelloDoneMessage*>(handshakeMessage);
			offsetInLogicalFragment +=
					serverHelloDoneMessage->getMessageLength();
			LOG_DEBUG
			<< "found server hello done!";
		} else if (handshakeType == pcpp::SSL_CLIENT_KEY_EXCHANGE) {
			pcpp::SSLClientKeyExchangeMessage *clientKeyExchangeMessage =
					dynamic_cast<pcpp::SSLClientKeyExchangeMessage*>(handshakeMessage);
			offsetInLogicalFragment +=
					clientKeyExchangeMessage->getMessageLength();
			LOG_DEBUG
			<< "found client key exchange with length "
					<< clientKeyExchangeMessage->getClientKeyExchangeParamsLength();
		} else if (handshakeType == pcpp::SSL_HANDSHAKE_UNKNOWN) {
			//TODO: right now assuming these are encrypted handshake messages;
			pcpp::SSLUnknownMessage *unknownMessage =
					dynamic_cast<pcpp::SSLUnknownMessage*>(handshakeMessage);
			offsetInLogicalFragment += unknownMessage->getMessageLength();
			LOG_DEBUG
			<< "encrypted handshake message";
			if (isClientMessage(i) && clientChangeCipherSpec) {
				clientEncryptedData += unknownMessage->getMessageLength();
				LOG_DEBUG
				<< "client encrypted " << std::to_string(clientEncryptedData);
			} else if (serverChangeCipherSpec) {
				serverEncryptedData += unknownMessage->getMessageLength();
				LOG_DEBUG
				<< "server encrypted " << std::to_string(serverEncryptedData);
			}
		}
	}
	return processedSSLHandshake;
}

void pcapfs::SslFile::resultPtrInit(bool processedSSLHandshake,
		pcpp::SSLVersion sslVersion, const std::shared_ptr<SslFile> &resultPtr,
		const FilePtr &filePtr, const std::string &cipherSuite, unsigned int i,
		Bytes &clientRandom, Index &idx, Bytes &serverRandom) {
	//search for master secret in candidates
	
    if (processedSSLHandshake) {
		Bytes masterSecret = searchCorrectMasterSecret(
				(char*) (clientRandom.data()), idx);
		if (!masterSecret.empty()) {
			Bytes keyMaterial = createKeyMaterial((char*) (masterSecret.data()),
					(char*) (clientRandom.data()),
					(char*) (serverRandom.data()), sslVersion.asUInt());
			//TODO: not good to add sslkey file directly into index!!!
			std::shared_ptr<SSLKeyFile> keyPtr = SSLKeyFile::createKeyFile(
					keyMaterial);
			idx.insert(keyPtr);
			resultPtr->keyIDinIndex = keyPtr->getIdInIndex();
			resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);
		}
	}
	
	resultPtr->setOffsetType(filePtr->getFiletype());
	resultPtr->setFiletype("ssl");
	resultPtr->cipherSuite = cipherSuite;
	resultPtr->sslVersion = sslVersion.asUInt();
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

std::vector<pcapfs::FilePtr> pcapfs::SslFile::parse(FilePtr filePtr, Index &idx) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
    Bytes data = filePtr->getBuffer();
    bool tlsTrafficDetected = false;
    bool visitedVirtualSslFile = false;
    std::vector<FilePtr> resultVector(0);

    //Step 1: detect ssl stream by checking for dst Port 443
    tlsTrafficDetected = isTLSTraffic(filePtr, tlsTrafficDetected);
    if (!tlsTrafficDetected) {
    	// No TLS Traffic found, continue with next.
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

				processedSSLHandshake = processTLSHandshake(
						processedSSLHandshake, i, clientChangeCipherSpec,
						serverChangeCipherSpec, handshakeLayer, clientRandom,
						offsetInLogicalFragment, serverRandom, cipherSuite,
						sslVersion, sslLayer, clientEncryptedData,
						serverEncryptedData);

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
							sslVersion, resultPtr, filePtr, cipherSuite, i,
							clientRandom, idx, serverRandom);
                    
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
                        size_t calculated_size = resultPtr->calculateProcessedSize(resultPtr->getFilesizeRaw(), idx);
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
                SimpleOffset soffset;
                soffset.id = filePtr->getIdInIndex();
                soffset.start = offset + bytesBeforeEncryptedData + offsetInLogicalFragment;
                
                LOG_TRACE << "[SOFFSET.START: " << offset << " + " <<  bytesBeforeEncryptedData << " + " << offsetInLogicalFragment << "]: " << soffset.start;

                soffset.length = encryptedDataLen;
                
                //if size is a mismatch => ssl packet is malformed
                //TODO: Better detection of malformed ssl packets
                if (soffset.length > sslLayer->getDataLen()) {
                    break;
                }
                
                resultPtr->offsets.push_back(soffset);
                
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
                size_t calculated_size = resultPtr->calculateProcessedSize(resultPtr->getFilesizeRaw(), idx);
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

    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
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




//TODO: not abstract enough to handle all ciphers?
//TODO: check if the key material is accessible for all ciphers and protocols.
/*
 * AES GCM mode has 40 byte key material - we will see if it still works.
 * 
 */







void pcapfs::SslFile::decryptDataNew(uint64_t virtual_file_offset, size_t length, char *cipherText, char* key_material, bool isClientMessage, PlainTextElement* output) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
	pcpp::SSLCipherSuite *cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByName(this->cipherSuite);
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
        
        /*
         * RC4 in SSL/TLS implemented cipher suites are decrypted here:
         */
        
        
        /*
         * Important note for export keys:
         * 
         * https://tools.ietf.org/html/rfc2246#section-6.3.1
         * 
         * they use the PRF for the IV!
         * 
         * 
         */
        case pcpp::SSL_SYM_RC4_128:
        {
            /*
             * This cipher flag SSL_SYM_RC4_128 in pcap plus plus should be able to decrypt the following cipher suites (all ciphers with RC4_128 bit keys):
             * Hint: Although this is correct in theory, in practice some of the ciphers are not supported by pcap++ nor openssl
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

            const int mac_size = 16;
            const int key_size = 16;
            
            unsigned char client_write_MAC_key[mac_size];
            unsigned char server_write_MAC_key[mac_size];
            unsigned char client_write_key[key_size];
            unsigned char server_write_key[key_size];

            memcpy(client_write_MAC_key,    key_material,                                   mac_size);
            memcpy(server_write_MAC_key,    key_material + mac_size,                        mac_size);
            memcpy(client_write_key,        key_material + 2*mac_size,                      key_size);
            memcpy(server_write_key,        key_material + 2*mac_size+key_size,             key_size);
            

            if(isClientMessage) {
                /*
                 * This is a client message
                 */

                Crypto::decrypt_RC4_128(
                		virtual_file_offset,
    					length,
    					cipherText,
						client_write_MAC_key,
						client_write_key,
						isClientMessage,
						output);


            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
            	Crypto::decrypt_RC4_128(
            			virtual_file_offset,
						length,
						cipherText,
						server_write_MAC_key,
						server_write_key,
						isClientMessage,
						output);

            }
            
            break;
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
                
                LOG_DEBUG << "decrypt_AES_128_CBC_NEW called with a client packet" << std::endl;
                Crypto::decrypt_AES_128_CBC(
                		virtual_file_offset,
						length,
						cipherText,
						client_write_MAC_key,
						client_write_key,
						client_write_IV,
						isClientMessage,
						output);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                LOG_DEBUG << "decrypt_AES_128_CBC_NEW called with a server packet" << std::endl;
                Crypto::decrypt_AES_128_CBC(
                		virtual_file_offset,
						length,
						cipherText,
						server_write_MAC_key,
						server_write_key,
						server_write_IV,
						isClientMessage,
						output);
                
            }
            break;
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
                
                LOG_DEBUG << "decrypt_AES_256_CBC_NEW called with a client packet" << std::endl;
                Crypto::decrypt_AES_256_CBC(
                		virtual_file_offset,
						length,
						cipherText,
						client_write_MAC_key,
						client_write_key,
						client_write_IV,
						isClientMessage,
						output);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                LOG_DEBUG << "decrypt_AES_256_CBC_NEW called with a server packet" << std::endl;
                Crypto::decrypt_AES_256_CBC(
                		virtual_file_offset,
						length,
						cipherText,
						server_write_MAC_key,
						server_write_key,
						server_write_IV,
						isClientMessage,
						output);
                
            }
            break;
        }
        
        case pcpp::SSL_SYM_AES_128_GCM:
        {
            /*
             * See https://www.ietf.org/rfc/rfc5246.txt, Page 26
             * 
             * 256_CBC should have the same except key material, 32 instead of 16, IV should be 16 bytes. (Page 84)
             */
            
            unsigned char client_write_key[16];
            unsigned char server_write_key[16];
            unsigned char client_write_IV[4];
            unsigned char server_write_IV[4];
            
            
            /*
             * Copy all bytes from the key material into our split key material.
             */
            
            memcpy(client_write_key,        key_material+0,         16);
            memcpy(server_write_key,        key_material+16,        16);
            memcpy(client_write_IV,         key_material+32,         4);
            memcpy(server_write_IV,         key_material+32+4,       4);
            
            
            //static for testing
            unsigned char public_nonce[12] = {0xd1 ,0xc9 ,0xc3 ,0x3f ,0x9d ,0x30 ,0x2f ,0x94 ,0x47 ,0xe2 ,0x1b ,0x9d};
            
            //static for testing
            unsigned char aad[13] = {0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x17 ,0x03 ,0x03 ,0x00 ,0x18};
            
            if(isClientMessage) {
                /*
                 * This is a client message
                 */
                
                LOG_DEBUG << "decrypt_AES_128_GCM_NEW called with a client packet" << std::endl;
                Crypto::decrypt_AES_128_GCM(
                		virtual_file_offset,
						length,
						cipherText,
						NULL,
						client_write_key,
						client_write_IV,
						aad,
						isClientMessage,
						output);
                
            } else {
                /*
                 * This is a server message, so we use server key etc.
                 */
                
                LOG_DEBUG << "decrypt_AES_128_GCM_NEW called with a server packet" << std::endl;
                Crypto::decrypt_AES_128_GCM(
                		virtual_file_offset,
						length,
						cipherText,
						NULL,
						server_write_key,
						server_write_IV,
						aad,
						isClientMessage,
						output);
                
            }
            break;
        }
        
        
        default:
            LOG_ERROR << "unsupported encryption found in ssl cipher suite: " << cipherSuite;
    }
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
}





pcapfs::Bytes pcapfs::SslFile::createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom, uint16_t sslVersion) {
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
    
    
    /*
     * The concrete openssl doc for this section:
     * 
     * https://www.openssl.org/docs/man1.1.0/man3/EVP_PKEY_CTX_set_tls1_prf_md.html
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
    
    
    switch(sslVersion) {
        
        /*
         * https://tools.ietf.org/html/rfc2246
         * 
         * 
         * 
         * 
         */
        
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
            LOG_INFO << "tls 1.0 detected\n";
            
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
            if (EVP_PKEY_derive_init(pctx) <= 0)
                LOG_ERROR << "Error1!" << std::endl;
            if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0)
            	LOG_ERROR << "Error2!" << std::endl;
            if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, masterSecret, 48) <= 0)
            	LOG_ERROR << "Error3!" << std::endl;
            if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seedSize) <= 0)
            	LOG_ERROR << "Error4!" << std::endl;
            if (EVP_PKEY_derive(pctx, keyMaterial.data(), &KEY_MATERIAL_SIZE) <= 0)
            	LOG_ERROR << "Error5!" << std::endl;
            ERR_print_errors_fp(stderr);
            
            EVP_PKEY_CTX_free(pctx);
            
            break;
        }
        case pcpp::SSLVersion::TLS1_1:
        {
            LOG_INFO << "tls 1.1 detected\n";
            
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
            if (EVP_PKEY_derive_init(pctx) <= 0)
            	LOG_ERROR << "Error1!" << std::endl;
            if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0)
            	LOG_ERROR << "Error2!" << std::endl;
            if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, masterSecret, 48) <= 0)
            	LOG_ERROR << "Error3!" << std::endl;
            if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seedSize) <= 0)
            	LOG_ERROR << "Error4!" << std::endl;
            if (EVP_PKEY_derive(pctx, keyMaterial.data(), &KEY_MATERIAL_SIZE) <= 0)
            	LOG_ERROR << "Error5!" << std::endl;
            ERR_print_errors_fp(stderr);
            
            EVP_PKEY_CTX_free(pctx);
            
            break;
        }
        case pcpp::SSLVersion::TLS1_2:
        {
            LOG_INFO << "tls 1.2 detected\n";
            
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
            if (EVP_PKEY_derive_init(pctx) <= 0)
            	LOG_ERROR << "Error1!" << std::endl;
            if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0)
            	LOG_ERROR << "Error2!" << std::endl;
            if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, masterSecret, 48) <= 0)
            	LOG_ERROR << "Error3!" << std::endl;
            if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seedSize) <= 0)
            	LOG_ERROR << "Error4!" << std::endl;
            if (EVP_PKEY_derive(pctx, keyMaterial.data(), &KEY_MATERIAL_SIZE) <= 0)
            	LOG_ERROR << "Error5!" << std::endl;
            ERR_print_errors_fp(stderr);
            
            EVP_PKEY_CTX_free(pctx);
            
            break;
        }
        case pcpp::SSLVersion::TLS1_3:
        {
        	LOG_INFO << "TLS 1.3 detected, currently not supported!";
        	break;
        }
        default:
        	pcpp::SSLVersion version(sslVersion);
            LOG_ERROR << "This type of TLS/SSL is not supported yet, we detected the ssl version code: " << version.toString() << std::endl;
    }
    
    LOG_INFO << "Key Material Size: " << KEY_MATERIAL_SIZE << std::endl;
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
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
		return read_decrypted_content(startOffset, length, idx, buf);
	} else {
		LOG_TRACE << "[NO KEY] start with reading raw, startOffset: " << startOffset << " and length: " << length;
		return read_raw(startOffset, length, idx, buf);
	}
}

size_t pcapfs::SslFile::read_raw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
    //TODO: right now this assumes each http file only contains ONE offset into a tcp stream
	LOG_TRACE << "read_raw offset size: " << offsets.size();
	Bytes write_me_to_file;
	size_t counter = 0;

	for(SimpleOffset offset: offsets) {
		LOG_TRACE << "start: " << offset.start << " length: " << offset.length;

		FilePtr filePtr = idx.get({offsetType, offset.id});
		Bytes temp_buffer(offset.length);
		//counter += filePtr->read(startOffset + offset.start, length, idx, buf);
		filePtr->read(offset.start, offset.length, idx, (char *) temp_buffer.data());
		write_me_to_file.insert(std::end(write_me_to_file), std::begin(temp_buffer), std::end(temp_buffer));
	}

	if (write_me_to_file.size() > 0) {
		memset(buf, 0, length);
		memcpy(buf, (const char*) write_me_to_file.data() + startOffset, length);
	} else {
		LOG_ERROR << "Empty buffer in read_raw, probably unwanted behavior.";
	}


    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
    //TODO: Check if this is correct at this point
    counter = length - startOffset;
    return counter;
}

size_t pcapfs::SslFile::read_decrypted_content(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    size_t position = 0;
    size_t posInFragment = 0;
    size_t fragment = 0;

    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
    std::vector< std::shared_ptr<CipherTextElement>> cipherTextVector(0);
    std::vector< std::shared_ptr<PlainTextElement>> plainTextVector(0);

    LOG_ERROR << "SSL File Read is called, with " << startOffset << " and length: " << length;

    LOG_TRACE << "[CACHE MISS] empty buffer, we do the regular data decryption.";

	// Init for the vectors with regular shared pointers
	for(auto& c : cipherTextVector) {
		c = std::make_shared<CipherTextElement>();
	}
	for(auto& p : plainTextVector) {
		p = std::make_shared<PlainTextElement>();
	}

	getFullCipherText(startOffset, length, idx, cipherTextVector);

	for(size_t i=0; i< cipherTextVector.size(); i++) {
		CipherTextElement *elem = cipherTextVector.at(i).get();
		elem->printMe();
	}

	decryptCiphertextVecToPlaintextVec(cipherTextVector, plainTextVector);

	int offset = 0;
	std::vector<Bytes> result;
	Bytes write_me_to_file;

	for(size_t i=0; i<plainTextVector.size(); i++) {
		PlainTextElement *elem = plainTextVector.at(i).get();
		elem->printMe();
		result.push_back(elem->plaintextBlock);
        write_me_to_file.insert(std::end(write_me_to_file), std::begin(result.at(i)), std::end(result.at(i)) );
		offset += elem->plaintextBlock.size();
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
        LOG_ERROR << "bytes_ref.size(): " << bytes_ref.size() << " " << "toRead: " << toRead;
        position += bytes_ref.size();
    }
    
    if(length > write_me_to_file.size()) {
        LOG_ERROR << "The requested file is larger than the decrypted resource. Diff: " << length - write_me_to_file.size() << "byte_counter: " << byte_counter;
    }
    
    
    
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
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
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
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
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
 */
size_t pcapfs::SslFile::read_for_size(uint64_t startOffset, size_t length, const Index &idx) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
    std::vector< std::shared_ptr<CipherTextElement>> cipherTextVector(0);
    std::vector< std::shared_ptr<PlainTextElement>> plainTextVector(0);

    // Init for the vectors with regular shared pointers
    for(auto& c : cipherTextVector) {
    	c = std::make_shared<CipherTextElement>();
    }
    for(auto& p : plainTextVector) {
		p = std::make_shared<PlainTextElement>();
	}
    
    getFullCipherText(startOffset, length, idx, cipherTextVector);
    
    for(size_t i=0; i< cipherTextVector.size(); i++) {
        CipherTextElement *elem = cipherTextVector.at(i).get();
        elem->printMe();
    }
    
    decryptCiphertextVecToPlaintextVec(cipherTextVector, plainTextVector);
    
    size_t offset = 0;
    LOG_TRACE << "entering file writer..." << std::endl;
    std::vector<Bytes> result;
    Bytes write_me_to_file;

    for(size_t i=0; i<plainTextVector.size(); i++) {
        PlainTextElement *elem = plainTextVector.at(i).get();
        elem->printMe();
        result.push_back(elem->plaintextBlock);
        offset += elem->plaintextBlock.size();
    }
    
    LOG_TRACE << "write_me_to_file.size(): " << write_me_to_file.size();
    LOG_TRACE << "offset size (this is the value we want to use later): " << offset;
    LOG_TRACE << "length: " << length;
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
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
size_t pcapfs::SslFile::getFullCipherText(uint64_t startOffset, size_t length, const Index &idx, std::vector< std::shared_ptr<CipherTextElement>> &outputCipherTextVector) {
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
	//TODO: support to decrypt CBC etc. stuff... Maybe decrypt all of the data or return parts? Depends on mode of operation
    //TODO: split read into readStreamcipher, readCFB, readCBC...
	/*TODO:
	 * Data is always completely returned, startOffset should always be zero. length is the full length.
	 * These are no request parameters as in an API design, these parameters are necessary to
	 *
	 */
    size_t fragment = 0;
    size_t posInFragment = 0;
    size_t position = 0;
    //int startOffset = 0;
    int counter = 0;
    
    LOG_DEBUG << "getFullCipherText is called\n";
    
    // start copying

    /*
     * Iterate with for loop over all fragements:
     * startOffset and length are irrelevant
     */
    while (position < startOffset + length && fragment < offsets.size()) {
        
    	LOG_DEBUG << "Read iteration number: " << counter << " fragment: " << fragment;
        
        counter++;
        size_t toRead = std::min(offsets[fragment].length - posInFragment, length - (position - startOffset));
        
        //TODO: is start=0 really good for missing data?
        // -> missing data should probably be handled in an exception?
        
        if (offsets[fragment].start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            LOG_INFO << "We have some missing TCP data: pcapfs::flags::MISSING_DATA was set";
        } else {
            
            /*
             * Read the bytes from the packets of the file (using the file pointer):
             * After this step, toDecrypt is filled with bytes.
             */
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->offsets.at(fragment).id});
            pcapfs::Bytes toDecrypt(this->offsets.at(fragment).length);
            filePtr->read(offsets.at(fragment).start, offsets.at(fragment).length, idx, (char *) toDecrypt.data());
            
            
            
            LOG_DEBUG << "offset at fragement " << fragment << " has following length: " << this->offsets.at(fragment).length << std::endl;
            
            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                pcapfs::Bytes decrypted;
                
                std::shared_ptr<SSLKeyFile> keyPtr = std::dynamic_pointer_cast<SSLKeyFile>(
                    idx.get({"sslkey", keyIDinIndex}));
                
                // Delete them in the vector which was provided!
                // In case you want to increase performance just precalculate the necessary speed before calling this function ('getFullCipherText') and pre-init the 'outputCipherTextVector'.
                
                std::shared_ptr<CipherTextElement> cte( new CipherTextElement());
                /*
                 * previousBytes:
                 * Decrypt e.g. RC4 at certain position.
                 *
                 * SO:
                 *
                 * previousBytes = ciphertext before current ciphertext element.
                 * This offset is needed to recalculate some (usually stream) ciphers correctly
                 *
                 */
                cte->virtual_file_offset = previousBytes[fragment];
                cte->cipherSuite = this->cipherSuite;
                cte->sslVersion = this->sslVersion;
                cte->cipherBlock = toDecrypt;
                cte->length = toRead;
                cte->keyMaterial.end();
                cte->keyMaterial = keyPtr->getKeyMaterial();
                cte->isClientBlock = isClientMessage(keyForFragment.at(fragment));
                outputCipherTextVector.push_back(cte);
            } else {
                LOG_ERROR << "NO KEYS FOUND FOR " << counter;
                //memcpy(buf + (position - startOffset), toDecrypt.data() + posInFragment, toRead);
            }
        }
        
        // set run variables in case next fragment is needed
        position += toRead;
        fragment++;
        posInFragment = 0;
    }
    
    LOG_ERROR << "READ IS DONE\n";
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
    /*
     * Filesize Raw is used, because we read the ciphertext aka the raw file.
     */
    if (startOffset + length < filesizeRaw) {
        return length;
    } else {
        return filesizeRaw - startOffset;
    }
}

/*
 * pcapfs::SslFile::decryptCiphertextToPlaintext
 * 
 * Encrypt the vector of bytes using the key material provided via every frame of the vector.
 * returns a vector of plaintext plus information such as if mac, alignment, padding is correct.
 * This is the vector which can be used by a user to get the plaintext with full information via the next function prototype.
 * 
 */
size_t pcapfs::SslFile::decryptCiphertextVecToPlaintextVec(
		std::vector< std::shared_ptr<CipherTextElement>> &cipherTextVector,
		std::vector< std::shared_ptr<PlainTextElement>> &outputPlainTextVector

	) {

	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");

	/*
	 * Cache: If not already instantiated, it will be created.
	 */

    int counter = 0;
    
    for (size_t i=0; i<cipherTextVector.size(); i++) {
        counter++;
        
        /*
         * This approach currently requires that we hold ciphertext and plaintext in memory. No file-based indexes are supported at this point.
         * refactor to shared_ptr?
         */
        
        CipherTextElement *element = cipherTextVector.at(i).get();
        std::shared_ptr<PlainTextElement> output( new PlainTextElement());
        

        /*
         * Padding is removed we don't need it anymore.
         */



        decryptDataNew(element->virtual_file_offset,
                        element->cipherBlock.size(),
                        (char *) element->cipherBlock.data(),
                        (char *) element->keyMaterial.data(),
                        element->isClientBlock,
                        output.get());
        
        output->virtual_file_offset = element->virtual_file_offset;
        output->isClientBlock = element->isClientBlock;
        output->cipherSuite = element->cipherSuite;
        output->sslVersion = element->sslVersion;
        
        outputPlainTextVector.push_back(output);

    }
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "left");
    return counter;
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
