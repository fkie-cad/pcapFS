#include "ssl.h"

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>

#include <assert.h>
#include <numeric>

#include "../filefactory.h"
#include "../logging.h"
#include "../crypto/decryptSymmetric.h"
#include "../crypto/ciphersuites.h"
#include "../crypto/handshakedata.h"
#include "../crypto/cryptutils.h"


std::string const pcapfs::SslFile::toString() {
	std::string ret;
	ret.append("SslFile object content:\n");

	ret.append("ciphersuite: ");
	ret.append(cipherSuite);
    ret.append("\n");

	ret.append("sslVersion: ");
	pcpp::SSLVersion v(sslVersion);
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
    std::vector<CiphertextPtr> cipherTextVector(0);
    std::vector<Bytes> result(0);

    getFullCipherText(idx, cipherTextVector);
    decryptCiphertextVecToPlaintextVec(cipherTextVector, result);

    return std::accumulate(result.begin(), result.end(), 0,
                            [](size_t counter, Bytes elem){ return counter + elem.size(); });
}


bool pcapfs::SslFile::isTLSTraffic(const FilePtr &filePtr) {
	// detect ssl stream by checking for dst Port 443
	// TODO: other detection method -> config file vs heuristic?
	if (filePtr->getProperty("dstPort") == "443") {
		return true;
	}
	return false;
}


void pcapfs::SslFile::processTLSHandshake(pcpp::SSLLayer *sslLayer, TLSHandshakeDataPtr &handshakeData, uint64_t &offset,
                                            const FilePtr &filePtr, const Index &idx){

    size_t currentHandshakeOffset = 0; // for extracting raw handshake data out of multiple handshake messages contained in one ssl layer
    pcpp::SSLHandshakeLayer *handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(sslLayer);
    if (!handshakeLayer) {
        LOG_ERROR << "Failed to extract TLS Handshake Layer";
        return;
    }
    uint64_t numHandshakeMessages = handshakeLayer->getHandshakeMessagesCount();
    if (numHandshakeMessages > 0){
        // add length of ssl record header
        offset += 5;
    }

	for (uint64_t j = 0; j < numHandshakeMessages; ++j) {
		pcpp::SSLHandshakeMessage *handshakeMessage = handshakeLayer->getHandshakeMessageAt(j);
        if (!handshakeMessage)
            continue;
        size_t messageLength = handshakeMessage->getMessageLength();
		pcpp::SSLHandshakeType handshakeType = handshakeMessage->getHandshakeType();

		if (handshakeType == pcpp::SSL_CLIENT_HELLO) {
            LOG_DEBUG << "found client hello message";
			pcpp::SSLClientHelloMessage *clientHelloMessage =
					dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMessage);
            if (!clientHelloMessage) {
                LOG_ERROR << "Failed to extract Client Hello Message";
                continue;
            }
            memcpy(handshakeData->clientRandom.data(),
                    clientHelloMessage->getClientHelloHeader()->random,
                    crypto::CLIENT_RANDOM_SIZE);

            pcpp::SSLServerNameIndicationExtension* sni = dynamic_cast<pcpp::SSLServerNameIndicationExtension*>(clientHelloMessage->getExtensionOfType(0));
            if (sni) {
                handshakeData->serverName = sni->getHostName();
            }
            if (numHandshakeMessages == 1) {
                handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                            sslLayer->getData()+5,
                                                            sslLayer->getData()+messageLength+5);
            } else {
                handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                            sslLayer->getData()+5+currentHandshakeOffset,
                                                            sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                currentHandshakeOffset += messageLength;
            }

		} else if (handshakeType == pcpp::SSL_SERVER_HELLO) {
            LOG_DEBUG << "found server hello message";
            pcpp::SSLServerHelloMessage *serverHelloMessage =
					dynamic_cast<pcpp::SSLServerHelloMessage*>(handshakeMessage);
            if (!serverHelloMessage) {
                LOG_ERROR << "Failed to extract Server Hello Message";
                continue;
            }
            memcpy(handshakeData->serverRandom.data(),
					serverHelloMessage->getServerHelloHeader()->random,
					crypto::SERVER_RANDOM_SIZE);
            if (serverHelloMessage->getCipherSuite())
                handshakeData->cipherSuite = serverHelloMessage->getCipherSuite();
			handshakeData->sslVersion = sslLayer->getRecordVersion().asUInt();
            handshakeData->processedTLSHandshake = true;

			LOG_TRACE << "We have " << serverHelloMessage->getExtensionCount() << " extensions!";
			if (serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_TRUNCATED_HMAC)) {
				LOG_TRACE << "Truncated HMAC extension is enabled";
                handshakeData->truncatedHmac = true;
			}
			if (serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_ENCRYPT_THEN_MAC)) {
				LOG_TRACE << "Encrypt-Then-Mac Extension is enabled";
                handshakeData->encryptThenMac = true;
			} else
				LOG_TRACE << "Encrypt-Then-Mac Extension is not enabled";
            if (serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_EXTENDED_MASTER_SECRET)) {
                LOG_TRACE << "Extended Master Secret Extension is enabled";
                handshakeData->extendedMasterSecret = true;
            } else
                LOG_TRACE << "Extended Master Secret Extension is not enabled";
            if (handshakeData->cipherSuite) {
                if (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA) {
                    if (numHandshakeMessages == 1) {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5,
                                                                    sslLayer->getData()+messageLength+5);
                    } else {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5+currentHandshakeOffset,
                                                                    sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                        currentHandshakeOffset += messageLength;
                    }
                }
            }

		} else if (handshakeType == pcpp::SSL_CLIENT_KEY_EXCHANGE) {
            LOG_DEBUG << "found client key exchange message";
            if (handshakeData->cipherSuite) {
                if (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA) {
                    pcpp::SSLClientKeyExchangeMessage *clientKeyExchangeMessage = dynamic_cast<pcpp::SSLClientKeyExchangeMessage*>(handshakeMessage);
                    if (!clientKeyExchangeMessage) {
                        LOG_ERROR << "Failed to extract Client Key Exchange Message";
                        continue;
                    }
                    if (clientKeyExchangeMessage->getClientKeyExchangeParams()) {
                        memcpy(handshakeData->rsaIdentifier.data(), clientKeyExchangeMessage->getClientKeyExchangeParams()+2, 8);

                        handshakeData->encryptedPremasterSecret.insert(handshakeData->encryptedPremasterSecret.begin(),
                                                                    clientKeyExchangeMessage->getClientKeyExchangeParams()+2,
                                                                    clientKeyExchangeMessage->getClientKeyExchangeParams()+clientKeyExchangeMessage->getClientKeyExchangeParamsLength());
                    }
                    if (handshakeData->extendedMasterSecret) {
                        if (numHandshakeMessages == 1) {
                            handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                        sslLayer->getData()+5,
                                                                        sslLayer->getData()+messageLength+5);
                        } else {
                            handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5+currentHandshakeOffset,
                                                                    sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                        }
                        handshakeData->sessionHash = crypto::calculateSessionHash(handshakeData);
                        if (handshakeData->sessionHash.empty())
                            LOG_ERROR << "Failed to calculate session hash. Look above why";
                    }
                }
            }

        } else if (handshakeType == pcpp::SSL_CERTIFICATE) {
            LOG_DEBUG << "found certiciate message";
            LOG_TRACE << "offset: " << offset;
            pcpp::SSLCertificateMessage *certificateMessage = dynamic_cast<pcpp::SSLCertificateMessage*>(handshakeMessage);
            if (!certificateMessage) {
                LOG_ERROR << "Failed to extract TLS Certificate Message";
                continue;
            }
            createCertFiles(filePtr, offset, certificateMessage, handshakeData, idx);
            if (handshakeData->cipherSuite) {
                if (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA &&
                    handshakeData->extendedMasterSecret && handshakeData->sessionHash.empty()) {
                    if (numHandshakeMessages == 1) {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5,
                                                                    sslLayer->getData()+messageLength+5);
                    } else {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5+currentHandshakeOffset,
                                                                    sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                        currentHandshakeOffset += messageLength;
                    }
                }
            }

        } else if (handshakeType == pcpp::SSL_HANDSHAKE_UNKNOWN) {
            // probably encrypted handshake message
			if (isClientMessage(handshakeData->iteration) && handshakeData->clientChangeCipherSpec) {
                handshakeData->clientEncryptedData += messageLength;
				LOG_DEBUG << "found encrypted handshake message, client encrypted " << std::to_string(handshakeData->clientEncryptedData);
			} else if (handshakeData->serverChangeCipherSpec) {
                handshakeData->serverEncryptedData += messageLength;
				LOG_DEBUG << "found encrypted handshake message, server encrypted " << std::to_string(handshakeData->serverEncryptedData);
			}
            if (handshakeData->cipherSuite) {
                if (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA && handshakeData->extendedMasterSecret &&
                    handshakeData->sessionHash.empty()) {
                    if (numHandshakeMessages == 1) {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5,
                                                                    sslLayer->getData()+messageLength+5);
                    } else {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5+currentHandshakeOffset,
                                                                    sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                        currentHandshakeOffset += messageLength;
                    }
                }
            }

		} else {
            LOG_DEBUG << "found handshake message of type " << handshakeMessage->getHandshakeType() << " and length " << messageLength;
            if (handshakeData->cipherSuite) {
                if (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA && handshakeData->extendedMasterSecret &&
                    handshakeData->sessionHash.empty()) {
                    if (numHandshakeMessages == 1) {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5,
                                                                    sslLayer->getData()+messageLength+5);
                    } else {
                        handshakeData->handshakeMessagesRaw.insert(handshakeData->handshakeMessagesRaw.end(),
                                                                    sslLayer->getData()+5+currentHandshakeOffset,
                                                                    sslLayer->getData()+messageLength+5+currentHandshakeOffset);
                        currentHandshakeOffset += messageLength;
                    }
                }
            }
        }
        offset += messageLength;
	}
}


size_t pcapfs::SslFile::calculateProcessedCertSize(const Index &idx) {
    Bytes rawData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    std::string pemString = crypto::convertToPem(rawData);
    return pemString.size();
}


void pcapfs::SslFile::createCertFiles(const FilePtr &filePtr, uint64_t offset, pcpp::SSLCertificateMessage* certificateMessage,
                                                                    const TLSHandshakeDataPtr &handshakeData, const Index &idx) {
    uint64_t offsetTemp = 0;

    offset += 7; //certificate message header length
    LOG_TRACE << "we have " << certificateMessage->getNumOfCertificates() << " certificates";

    for (int i = 0; i < certificateMessage->getNumOfCertificates(); ++i) {
        std::shared_ptr<SslFile> certPtr = std::make_shared<SslFile>();
        pcpp::SSLx509Certificate* certificate = certificateMessage->getCertificate(i);

        offsetTemp += 3; // length field in front of each certificate
        LOG_TRACE << "cert " << i << ": length: " << certificate->getDataLength();

        Fragment fragment;
        fragment.id = filePtr->getIdInIndex();
        fragment.start = offset + offsetTemp;
        fragment.length = certificate->getDataLength();

        certPtr->fragments.push_back(fragment);
        certPtr->setFilesizeRaw(fragment.length);
        certPtr->setFilesizeProcessed(fragment.length);
        certPtr->setFiletype("ssl");
        certPtr->setFilename("SSLCertificate");
        certPtr->setOffsetType("tcp");
        certPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
	    certPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
	    certPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
	    certPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
	    certPtr->setProperty("protocol", "ssl");
        if (!handshakeData->serverName.empty())
            certPtr->setProperty("domain", handshakeData->serverName);
        certPtr->flags.set(pcapfs::flags::IS_METADATA);
        certPtr->flags.set(pcapfs::flags::PROCESSED);

        certPtr->setFilesizeProcessed(certPtr->calculateProcessedCertSize(idx));

        handshakeData->certificates.push_back(certPtr);
        handshakeData->serverCertificate.insert(handshakeData->serverCertificate.end(),
                                                certificate->getData(), certificate->getData()+certificate->getDataLength());

        offsetTemp += certificate->getDataLength();
    }
}


void pcapfs::SslFile::initResultPtr(const std::shared_ptr<SslFile> &resultPtr, const FilePtr &filePtr, const TLSHandshakeDataPtr &handshakeData, Index &idx){
	//search for master secret in candidates
    if (handshakeData->processedTLSHandshake && handshakeData->cipherSuite) {
		const Bytes masterSecret = searchCorrectMasterSecret(handshakeData, idx);
		if (!masterSecret.empty() && isSupportedCipherSuite(handshakeData->cipherSuite)) {
			Bytes keyMaterial = crypto::createKeyMaterial(masterSecret, handshakeData, false);
            if(!keyMaterial.empty()) {
			    //TODO: not good to add sslkey file directly into index!!!
			    std::shared_ptr<SSLKeyFile> keyPtr = SSLKeyFile::createKeyFile(
			    		keyMaterial);
			    idx.insert(keyPtr);
			    resultPtr->setKeyIDinIndex(keyPtr->getIdInIndex());
			    resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            } else
                LOG_ERROR << "Failed to create key material. Look above why" << std::endl;
		}
	}
    resultPtr->setOffsetType(filePtr->getFiletype());
    resultPtr->setFiletype("ssl");
    resultPtr->setCipherSuite(handshakeData->cipherSuite->asString());
    resultPtr->encryptThenMacEnabled = handshakeData->encryptThenMac;
    resultPtr->truncatedHmacEnabled = handshakeData->truncatedHmac;
    resultPtr->setSslVersion(handshakeData->sslVersion);
    resultPtr->setFilename("SSL");
    resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    resultPtr->setProperty("protocol", "ssl");
    if (!handshakeData->serverName.empty())
        resultPtr->setProperty("domain", handshakeData->serverName);
    resultPtr->setTimestamp(filePtr->connectionBreaks.at(handshakeData->iteration).second);

    if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
        resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
    }
}


bool pcapfs::SslFile::isSupportedCipherSuite(const pcpp::SSLCipherSuite* cipherSuite) {
    if (!cipherSuite)
        return false;
    if (crypto::supportedCipherSuiteIds.find(cipherSuite->getID()) == crypto::supportedCipherSuiteIds.end()) {
        LOG_ERROR << "unsupported cipher suite for decryption: " << cipherSuite->asString();
        return false;
    }
    return true;
}


std::vector<pcapfs::FilePtr> pcapfs::SslFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    // detect ssl stream by checking for dst Port 443
    if(!isTLSTraffic(filePtr)) {
        return resultVector;
    }

    size_t size = 0;
    size_t numElements = filePtr->connectionBreaks.size();
    bool visitedVirtualSslFile = false;
    std::shared_ptr<SslFile> resultPtr = nullptr;
    TLSHandshakeDataPtr handshakeData = std::make_shared<crypto::TLSHandshakeData>();

    // process all logical breaks in underlying virtual file
    for (unsigned int i = 0; i < numElements; ++i) {
        LOG_DEBUG << "processing element " << std::to_string(i+1) << " of " << std::to_string(numElements);
        uint64_t &offset = filePtr->connectionBreaks.at(i).first;

        // get correct size (depending on element processed)
        if (i == numElements - 1) {
            size = filePtr->getFilesizeRaw() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        //connection break has wrong size if content is encrypted
        LOG_DEBUG << "connectionBreaks Size: " << size;

        // one logical fragment may contain multiple ssl layer messages
        pcpp::SSLLayer *sslLayer = pcpp::SSLLayer::createSSLMessage((uint8_t *) data.data() + offset, size, nullptr, nullptr);
        bool connectionBreakOccured = true;
        handshakeData->iteration = i;

        while (sslLayer != nullptr) {
            pcpp::SSLRecordType recType = sslLayer->getRecordType();

            //Step 5: parse the corresponding ssl message
            if (recType == pcpp::SSL_HANDSHAKE) {
                processTLSHandshake(sslLayer, handshakeData, offset, filePtr, idx);

            } else if (recType == pcpp::SSL_CHANGE_CIPHER_SPEC) {
                LOG_DEBUG << "found change cipher spec message";
                if (isClientMessage(i)) {
                    LOG_DEBUG << "client starting encryption now!";
                    handshakeData->clientChangeCipherSpec = true;
                } else {
                    LOG_DEBUG << "server starting encryption now!";
                    handshakeData->serverChangeCipherSpec = true;
                }
                // length of change cipher spec is always 1, add ssl record layer header length
                offset += 6;

            } else if (recType == pcpp::SSL_APPLICATION_DATA) {

                pcpp::SSLApplicationDataLayer *applicationDataLayer =
                        dynamic_cast<pcpp::SSLApplicationDataLayer *>(sslLayer);
                if (!applicationDataLayer) {
                    LOG_ERROR << "dynamic_cast to ssl app data layer failed";
                    offset += sslLayer->getLayerPayloadSize();
                    continue;
                }

                uint64_t encryptedDataLen = applicationDataLayer->getEncryptedDataLen();
                uint64_t completeSSLLen = applicationDataLayer->getHeaderLen();

                LOG_TRACE << "applicationDataLayer->getEncryptedDataLen(): " << applicationDataLayer->getEncryptedDataLen();
                LOG_TRACE << "applicationDataLayer->getHeaderLen(): " << applicationDataLayer->getHeaderLen();

                uint64_t bytesBeforeEncryptedData = completeSSLLen - encryptedDataLen;
                LOG_TRACE << "bytesBeforeEncryptedData: " << bytesBeforeEncryptedData;

                //create ssl application file
                //TODO: does client always send first?
                if (!resultPtr) {
                    if (handshakeData->sslVersion == 0)
                        // possible that extraction of sslVersion was not done in advance
                        handshakeData->sslVersion = sslLayer->getRecordVersion().asUInt();

                    resultPtr = std::make_shared<SslFile>();
                    initResultPtr(resultPtr, filePtr, handshakeData, idx);

                    //init with 0
                    resultPtr->filesizeProcessed = 0;
                    resultPtr->filesizeRaw = 0;
                }

                if (resultPtr->flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                    LOG_INFO << "[PARSING TLS APP DATA **WITH** KEY]";
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
                fragment.start = offset + bytesBeforeEncryptedData;
                fragment.length = encryptedDataLen;

                // if size is a mismatch => ssl packet is malformed
                // TODO: Better detection of malformed ssl packets
                if (fragment.length > sslLayer->getDataLen()) {
                    break;
                }

                resultPtr->fragments.push_back(fragment);

                LOG_DEBUG << "found app data";
                if (isClientMessage(i) && handshakeData->clientChangeCipherSpec) {
                    resultPtr->previousBytes.push_back(handshakeData->clientEncryptedData);
                    handshakeData->clientEncryptedData += encryptedDataLen;
                    resultPtr->keyForFragment.push_back(0);
                    LOG_DEBUG << "client encrypted " << std::to_string(handshakeData->clientEncryptedData);
                } else if (!isClientMessage(i) && handshakeData->serverChangeCipherSpec){
                    resultPtr->previousBytes.push_back(handshakeData->serverEncryptedData);
                    handshakeData->serverEncryptedData += encryptedDataLen;
                    resultPtr->keyForFragment.push_back(1);
                    LOG_DEBUG << "server encrypted " << std::to_string(handshakeData->serverEncryptedData);
                }

                offset += completeSSLLen;

                resultPtr->setFilesizeRaw(resultPtr->getFilesizeRaw() + encryptedDataLen);

				LOG_DEBUG << "Full SSL File afterwards:\n" << resultPtr->toString();
			}

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
                LOG_DEBUG << "filesizeprocessed: " << calculated_size;
                resultPtr->setFilesizeProcessed(calculated_size);
            }
        }
    }

    //TODO: multiple ssl streams in one tcp stream?!
    if (resultPtr) {
        resultVector.push_back(resultPtr);
    }

    std::copy(handshakeData->certificates.begin(), handshakeData->certificates.end(),
                std::back_inserter(resultVector));

    return resultVector;
}


//Returns the correct Master Secret out of a bunch of candidates
pcapfs::Bytes const pcapfs::SslFile::searchCorrectMasterSecret(const TLSHandshakeDataPtr &handshakeData, const Index &idx) {

    bool isRsaKeyX = (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA);
    std::vector<pcapfs::FilePtr> keyFiles = idx.getCandidatesOfType("sslkey");

    for (auto &keyFile: keyFiles) {
        std::shared_ptr<SSLKeyFile> sslKeyFile = std::dynamic_pointer_cast<SSLKeyFile>(keyFile);
        if (!sslKeyFile) {
            LOG_ERROR << "dynamic_pointer_cast failed for ssl key file";
            continue;
        }
        if (sslKeyFile->getClientRandom() == handshakeData->clientRandom){
            return sslKeyFile->getMasterSecret();
        } else if (isRsaKeyX) {
            if (sslKeyFile->getRsaIdentifier() == handshakeData->rsaIdentifier) {
                return crypto::createKeyMaterial(sslKeyFile->getPreMasterSecret(), handshakeData, true);
            } else if (crypto::matchPrivateKey(sslKeyFile->getRsaPrivateKey(), handshakeData->serverCertificate)) {
                return crypto::createKeyMaterial(crypto::rsaPrivateDecrypt(handshakeData->encryptedPremasterSecret,
                                                sslKeyFile->getRsaPrivateKey(), true), handshakeData, true);
            }
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
 * symmetric ssl encryption enum in pcap plus plus:
 * https://seladb.github.io/PcapPlusPlus-Doc/Documentation/a00202.html#ac4f9e906dad88c5eb6a34390e5ea54b7
 *
 */


int pcapfs::SslFile::decryptData(const CiphertextPtr &input, Bytes &output) {
	pcpp::SSLCipherSuite *cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByName(getCipherSuite());

    switch (cipherSuite->getSymKeyAlg()) {
        case pcpp::SSL_SYM_RC4_128:
        {
            crypto::decrypt_RC4_128(input, output, cipherSuite->getMACAlg());
            break;
        }
        case pcpp::SSL_SYM_AES_128_CBC:
        {
            crypto::decrypt_AES_CBC(input, output, cipherSuite->getMACAlg(), 16);
            break;
        }
        case pcpp::SSL_SYM_AES_256_CBC:
        {
            crypto::decrypt_AES_CBC(input, output, cipherSuite->getMACAlg(), 32);
            break;
        }
        case pcpp::SSL_SYM_AES_128_GCM:
        {
            crypto::decrypt_AES_GCM(input, output, 16);
            break;
        }
        case pcpp::SSL_SYM_AES_256_GCM:
        {
            crypto::decrypt_AES_GCM(input, output, 32);
            break;
        }
        default:
            LOG_ERROR << "unsupported encryption found in ssl cipher suite: " << cipherSuite->asString();
            return 0;
    }
    return 1;
}


size_t pcapfs::SslFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

    if(flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
        LOG_TRACE << "[USING KEY] start with reading decrypted content, startOffset: " << startOffset << " and length: " << length;

        // Here, length is the plaintext length
        return readDecryptedContent(startOffset, length, idx, buf);
	} else {
		LOG_TRACE << "[NO KEY] start with reading raw, startOffset: " << startOffset << " and length: " << length;

        // Here, length is the ciphertext length
        if(flags.test(pcapfs::flags::IS_METADATA)) {
            return readCertificate(startOffset, length, idx, buf);
        } else {
            return readRaw(startOffset, length, idx, buf);
        }
	}
}


size_t pcapfs::SslFile::readCertificate(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    std::string pemString = crypto::convertToPem(rawData);
    size_t readCount = std::min((size_t) pemString.length() - startOffset, length);
    memcpy(buf, pemString.c_str() + startOffset, length);
    return readCount;
}


size_t pcapfs::SslFile::readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
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


size_t pcapfs::SslFile::readDecryptedContent(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

    bool buffer_needs_content = std::all_of(buffer.cbegin(), buffer.cend(),
                                            [](const auto &elem) { return elem == 0; });
    if(buffer_needs_content == false) {

        LOG_DEBUG << "[BUFFER HIT] buffer is this:" << std::endl;
        assert(buffer.size() == filesizeProcessed);

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

    size_t position = 0;
    size_t posInFragment = 0;
    size_t fragment = 0;
    std::vector<CiphertextPtr> cipherTextVector(0);
    std::vector<Bytes> result(0);

    getFullCipherText(idx, cipherTextVector);
    decryptCiphertextVecToPlaintextVec(cipherTextVector, result);

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
        fragment++;
        posInFragment = 0;
        LOG_DEBUG << "bytes_ref.size(): " << bytes_ref.size() << " " << "toRead: " << toRead;
        position += bytes_ref.size();
    }

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
 * The function gets the full TLS application layer stream into a vector.
 * Each element in the vector represents one decrypted packet, containing an alternating stream of the packets from client and server.
 */
size_t pcapfs::SslFile::getFullCipherText(const Index &idx, std::vector<CiphertextPtr> &outputCipherTextVector) {
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
            // Read the bytes from the packets of the file (using the file pointer)
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
            pcapfs::Bytes toDecrypt(this->fragments.at(fragment).length);
            filePtr->read(fragments.at(fragment).start, fragments.at(fragment).length, idx, (char *) toDecrypt.data());

            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {

                std::shared_ptr<SSLKeyFile> keyPtr = std::dynamic_pointer_cast<SSLKeyFile>(
                    idx.get({"sslkey", getKeyIDinIndex()}));

                CiphertextPtr cte = std::make_shared<CipherTextElement>();
                cte->setVirtualFileOffset(previousBytes[fragment]);
                cte->setCipherBlock(toDecrypt);
                cte->setLength(toRead);
                cte->setKeyMaterial(keyPtr->getKeyMaterial());
                cte->isClientBlock = isClientMessage(keyForFragment.at(fragment));
                cte->encryptThenMacEnabled = this->encryptThenMacEnabled;
                cte->truncatedHmacEnabled = this->truncatedHmacEnabled;
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
            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
                size_t counter_for_bytes_output_ciphertext = std::accumulate(outputCipherTextVector.begin(), outputCipherTextVector.end(), 0,
                                                        [](size_t counter, auto elem){ return counter + elem->getLength(); });
                size_t counter_for_fragments = std::accumulate(fragments.begin(), fragments.end(), 0,
                                                        [](size_t counter, Fragment frag){ return counter + frag.length; });
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
 * Decrypt the vector of bytes using the key material provided via every frame of the vector.
 * returns a vector of the plaintext.
 */
void pcapfs::SslFile::decryptCiphertextVecToPlaintextVec(
		const std::vector<CiphertextPtr> &cipherTextVector,
		std::vector<Bytes> &outputPlainTextVector) {

    for (size_t i=0; i<cipherTextVector.size(); i++) {
        CiphertextPtr element = cipherTextVector.at(i);
        Bytes output(0);

        if(!decryptData(element, output)) {
            // unsupported encryption, should not happen
            output.insert(output.end(), element->getCipherBlock().begin(), element->getCipherBlock().end());
        }
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
    archive << (encryptThenMacEnabled ? 1 : 0);
    archive << (truncatedHmacEnabled ? 1 : 0);
    archive << keyIDinIndex;
    archive << previousBytes;
    archive << keyForFragment;
}


void pcapfs::SslFile::deserialize(boost::archive::text_iarchive &archive) {
    int i, j = 0;
    VirtualFile::deserialize(archive);
    archive >> cipherSuite;
    archive >> sslVersion;
    archive >> i;
    encryptThenMacEnabled = i ? true : false;
    archive >> j;
    truncatedHmacEnabled = j ? true : false;
    archive >> keyIDinIndex;
    archive >> previousBytes;
    archive >> keyForFragment;
}
