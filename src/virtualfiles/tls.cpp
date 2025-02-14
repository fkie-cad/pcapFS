#include "tls.h"
#include "../filefactory.h"
#include "../logging.h"
#include "../crypto/decrypt_symmetric.h"
#include "../crypto/ciphersuites.h"
#include "../crypto/handshakedata.h"
#include "../crypto/cryptutils.h"
#include "../crypto/ja4.h"

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>
#include <assert.h>
#include <numeric>
#include <regex>
#include <algorithm>


std::string const pcapfs::TlsFile::toString() {
	std::string ret;
	ret.append("TlsFile object content:\n");

	ret.append("ciphersuite: ");
	ret.append(cipherSuite);
    ret.append("\n");

	ret.append("tlsVersion: ");
	pcpp::SSLVersion v(tlsVersion);
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


size_t pcapfs::TlsFile::calculateProcessedSize(const Index &idx) {
    std::vector<CiphertextPtr> cipherTextVector(0);
    std::vector<Bytes> result(0);

    getFullCipherText(idx, cipherTextVector);
    decryptCiphertextVecToPlaintextVec(cipherTextVector, result);

    return std::accumulate(result.begin(), result.end(), 0,
                            [](size_t counter, Bytes elem){ return counter + elem.size(); });
}


bool pcapfs::TlsFile::isTLSTraffic(const FilePtr &filePtr, const Bytes &data) {
    if (filePtr->getProperty(prop::protocol) != "tcp")
        return false;
    if (!config.checkNonDefaultPorts)
        return (filePtr->getProperty(prop::srcPort) == "443" || filePtr->getProperty(prop::dstPort) == "443");
    else if (data.size() > 5) {
        LOG_TRACE << "try to detect TLS traffic with regex";
        try {
            // match TLS record layer header
            if (std::regex_match(std::string(&data.at(0), &data.at(5)),
                std::regex("^[\\x14-\\x17]\x03[\\x01-\\x03][\\x00-\\x40].$"))) {
                    const uint16_t recordLength = be16toh(*(uint16_t*) &data.at(3));
                    LOG_TRACE << "recordLength: " << recordLength;
                    if ((size_t)(recordLength + 5) <= data.size()) {
                        LOG_TRACE << "detected TLS traffic";
                        return true;
                    } else
                        return false;
            } else {
                LOG_TRACE << "no match";
                return false;
            }
        } catch (const std::regex_error &err) {
            LOG_WARNING << "Regex Error in TLS: " << err.what();
            return false;
        }
    } else
        return false;
}


void pcapfs::TlsFile::processTLSHandshake(pcpp::SSLLayer *sslLayer, TLSHandshakeDataPtr &handshakeData, uint64_t &offset,
                                            const FilePtr &filePtr, const Index &idx){

    size_t currentHandshakeOffset = 0; // for extracting raw handshake data out of multiple handshake messages contained in one ssl layer
    const pcpp::SSLHandshakeLayer *handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer *>(sslLayer);
    if (!handshakeLayer) {
        LOG_ERROR << "Failed to extract TLS Handshake Layer";
        return;
    }
    const uint64_t numHandshakeMessages = handshakeLayer->getHandshakeMessagesCount();
    if (numHandshakeMessages > 0){
        // add length of tls record header
        offset += 5;
    }

	for (uint64_t j = 0; j < numHandshakeMessages; ++j) {
		pcpp::SSLHandshakeMessage *handshakeMessage = handshakeLayer->getHandshakeMessageAt(j);
        if (!handshakeMessage)
            continue;
        const size_t messageLength = handshakeMessage->getMessageLength();
		const pcpp::SSLHandshakeType handshakeType = handshakeMessage->getHandshakeType();

		if (handshakeType == pcpp::SSL_CLIENT_HELLO) {
            LOG_DEBUG << "found client hello message";
			const pcpp::SSLClientHelloMessage *clientHelloMessage =
					dynamic_cast<pcpp::SSLClientHelloMessage*>(handshakeMessage);
            if (!clientHelloMessage) {
                LOG_ERROR << "Failed to extract Client Hello Message";
                continue;
            }
            memcpy(handshakeData->clientRandom.data(),
                    clientHelloMessage->getClientHelloHeader()->random,
                    crypto::CLIENT_RANDOM_SIZE);

            const pcpp::SSLServerNameIndicationExtension* sni =
                    dynamic_cast<pcpp::SSLServerNameIndicationExtension*>(clientHelloMessage->getExtensionOfType(0));
            if (sni) {
                handshakeData->serverName = sni->getHostName();
            }
            pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint fingerprint = clientHelloMessage->generateTLSFingerprint();
            handshakeData->ja3 = fingerprint.toMD5();
            handshakeData->ja4 = ja4::calculateJa4(fingerprint, handshakeData->serverName, clientHelloMessage->getExtensionOfType(16),
                                                clientHelloMessage->getExtensionOfType(13), clientHelloMessage->getExtensionOfType(43));

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
            const pcpp::SSLServerHelloMessage *serverHelloMessage =
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
			handshakeData->tlsVersion = sslLayer->getRecordVersion().asUInt();
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

            pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint fingerprint = serverHelloMessage->generateTLSFingerprint();
            handshakeData->ja3s = fingerprint.toMD5();
            handshakeData->ja4s = ja4::calculateJa4S(fingerprint, serverHelloMessage->getExtensionOfType(16),
                                                serverHelloMessage->getExtensionOfType(43));

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
                    const pcpp::SSLClientKeyExchangeMessage *clientKeyExchangeMessage =
                            dynamic_cast<pcpp::SSLClientKeyExchangeMessage*>(handshakeMessage);
                    if (!clientKeyExchangeMessage) {
                        LOG_ERROR << "Failed to extract Client Key Exchange Message";
                        continue;
                    }
                    if (clientKeyExchangeMessage->getClientKeyExchangeParams()) {
                        memcpy(handshakeData->rsaIdentifier.data(), clientKeyExchangeMessage->getClientKeyExchangeParams()+2, 8);

                        handshakeData->encryptedPremasterSecret.insert(handshakeData->encryptedPremasterSecret.begin(),
                                                                    clientKeyExchangeMessage->getClientKeyExchangeParams()+2,
                                                                    clientKeyExchangeMessage->getClientKeyExchangeParams()+
                                                                        clientKeyExchangeMessage->getClientKeyExchangeParamsLength());
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
            const pcpp::SSLCertificateMessage *certificateMessage = dynamic_cast<pcpp::SSLCertificateMessage*>(handshakeMessage);
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



std::pair<size_t, std::string> pcapfs::TlsFile::calculateProcessedCertSize(const Index &idx) {
    Bytes rawData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    std::string ja4x = ja4::calculateJa4X(rawData);
    std::string pemString = crypto::convertToPem(rawData);
    return std::make_pair(pemString.size(), ja4x);
}


void pcapfs::TlsFile::createCertFiles(const FilePtr &filePtr, uint64_t offset, const pcpp::SSLCertificateMessage* certificateMessage,
                                        TLSHandshakeDataPtr &handshakeData, const Index &idx) {
    uint64_t offsetTemp = 0;

    offset += 7; //certificate message header length
    LOG_TRACE << "we have " << certificateMessage->getNumOfCertificates() << " certificates";

    for (int i = 0; i < certificateMessage->getNumOfCertificates(); ++i) {
        std::shared_ptr<TlsFile> certPtr = std::make_shared<TlsFile>();
        const pcpp::SSLx509Certificate* certificate = certificateMessage->getCertificate(i);

        offsetTemp += 3; // length field in front of each certificate
        LOG_TRACE << "cert " << i << ": length: " << certificate->getDataLength();

        Fragment fragment;
        fragment.id = filePtr->getIdInIndex();
        fragment.start = offset + offsetTemp;
        fragment.length = certificate->getDataLength();

        certPtr->fragments.push_back(fragment);
        certPtr->setFilesizeRaw(fragment.length);
        certPtr->setFilesizeProcessed(fragment.length);
        certPtr->setFiletype("tls");
        certPtr->setFilename("TLSCertificate");
        certPtr->setOffsetType("tcp");
        certPtr->setProperty(prop::srcIP, filePtr->getProperty(prop::srcIP));
	    certPtr->setProperty(prop::dstIP, filePtr->getProperty(prop::dstIP));
	    certPtr->setProperty(prop::srcPort, filePtr->getProperty(prop::srcPort));
	    certPtr->setProperty(prop::dstPort, filePtr->getProperty(prop::dstPort));
	    certPtr->setProperty(prop::protocol, "tls");
        if (!handshakeData->serverName.empty())
            certPtr->setProperty(prop::domain, handshakeData->serverName);
        if (!handshakeData->ja3.empty())
            certPtr->setProperty(prop::ja3, handshakeData->ja3);
        if (!handshakeData->ja3s.empty())
            certPtr->setProperty(prop::ja3s, handshakeData->ja3s);
        if (!handshakeData->ja4.empty())
            certPtr->setProperty(prop::ja4, handshakeData->ja4);
        if (!handshakeData->ja4s.empty())
            certPtr->setProperty(prop::ja4s, handshakeData->ja4s);
        certPtr->flags.set(pcapfs::flags::IS_METADATA);
        certPtr->flags.set(pcapfs::flags::PROCESSED);

        auto tmp = certPtr->calculateProcessedCertSize(idx);
        certPtr->setFilesizeProcessed(tmp.first);
        if (!tmp.second.empty()) {
            certPtr->setProperty(prop::ja4x, tmp.second);
            if (i == 0) {
                // take ja4x fingerprint of first certificate of the chain
                // as corresponding property for the TLS connection
                handshakeData->ja4x = tmp.second;
            }
        }
        handshakeData->certificates.push_back(certPtr);
        handshakeData->serverCertificate.insert(handshakeData->serverCertificate.end(),
                                                certificate->getData(),
                                                certificate->getData()+certificate->getDataLength());

        offsetTemp += certificate->getDataLength();
    }
}


void pcapfs::TlsFile::initResultPtr(const std::shared_ptr<TlsFile> &resultPtr, const FilePtr &filePtr, const TLSHandshakeDataPtr &handshakeData, Index &idx){
	//search for master secret in candidates
    if ((config.getDecodeMapFor("tls").empty() || filePtr->meetsDecodeMapCriteria("tls")) &&
        handshakeData->processedTLSHandshake && handshakeData->cipherSuite) {
        // when no decode config for tls is supplied we try to decrypt all tls traffic (with the resp. keys)
        // when an tls decode config is supplied we only decrypt tls traffic which meets the given config
		const Bytes masterSecret = searchCorrectMasterSecret(handshakeData, idx);
		if (!masterSecret.empty() && isSupportedCipherSuite(handshakeData->cipherSuite)) {
		    const Bytes keyMaterial = crypto::createKeyMaterial(masterSecret, handshakeData, false);
            if(!keyMaterial.empty()) {
		        std::shared_ptr<TLSKeyFile> keyPtr = TLSKeyFile::createKeyFile(
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
    resultPtr->setFiletype("tls");
    if (handshakeData->cipherSuite)
        resultPtr->setCipherSuite(handshakeData->cipherSuite->asString());
    if (!handshakeData->ja3.empty())
        resultPtr->setProperty(prop::ja3, handshakeData->ja3);
    if (!handshakeData->ja3s.empty())
        resultPtr->setProperty(prop::ja3s, handshakeData->ja3s);
    if (!handshakeData->ja4.empty())
        resultPtr->setProperty(prop::ja4, handshakeData->ja4);
    if (!handshakeData->ja4s.empty())
        resultPtr->setProperty(prop::ja4s, handshakeData->ja4s);
    if (!handshakeData->ja4x.empty())
        resultPtr->setProperty(prop::ja4x, handshakeData->ja4x);
    resultPtr->encryptThenMacEnabled = handshakeData->encryptThenMac;
    resultPtr->truncatedHmacEnabled = handshakeData->truncatedHmac;
    resultPtr->setTlsVersion(handshakeData->tlsVersion);
    resultPtr->setFilename("TLS");
    resultPtr->setProperty(prop::srcIP, filePtr->getProperty(prop::srcIP));
    resultPtr->setProperty(prop::dstIP, filePtr->getProperty(prop::dstIP));
    resultPtr->setProperty(prop::srcPort, filePtr->getProperty(prop::srcPort));
    resultPtr->setProperty(prop::dstPort, filePtr->getProperty(prop::dstPort));
    resultPtr->setProperty(prop::protocol, "tls");
    if (!handshakeData->serverName.empty())
        resultPtr->setProperty(prop::domain, handshakeData->serverName);
    resultPtr->setTimestamp(filePtr->connectionBreaks.at(handshakeData->iteration).second);

    if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
        resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
    }
}


bool pcapfs::TlsFile::isSupportedCipherSuite(const pcpp::SSLCipherSuite* cipherSuite) {
    if (!cipherSuite)
        return false;
    if (crypto::supportedCipherSuiteIds.find(cipherSuite->getID()) == crypto::supportedCipherSuiteIds.end()) {
        LOG_ERROR << "unsupported cipher suite for decryption: " << cipherSuite->asString();
        return false;
    }
    return true;
}


std::vector<pcapfs::FilePtr> pcapfs::TlsFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    // detect tls stream by checking for dst Port 443
    if(!isTLSTraffic(filePtr, data)) {
        return resultVector;
    }

    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();
    bool visitedVirtualTlsFile = false;
    std::shared_ptr<TlsFile> resultPtr = nullptr;
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

        // one logical fragment may contain multiple tls layer messages
        pcpp::SSLLayer *sslLayer = pcpp::SSLLayer::createSSLMessage((uint8_t *) data.data() + offset, size, nullptr, nullptr);
        bool connectionBreakOccured = true;
        handshakeData->iteration = i;

        while (sslLayer != nullptr) {
            const pcpp::SSLRecordType recType = sslLayer->getRecordType();

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
                // length of change cipher spec is always 1, add tls record layer header length
                offset += 6;

            } else if (recType == pcpp::SSL_APPLICATION_DATA) {

                const pcpp::SSLApplicationDataLayer *applicationDataLayer =
                        dynamic_cast<pcpp::SSLApplicationDataLayer *>(sslLayer);
                if (!applicationDataLayer) {
                    LOG_ERROR << "dynamic_cast to ssl app data layer failed";
                    offset += sslLayer->getLayerPayloadSize();
                    continue;
                }

                const uint64_t encryptedDataLen = applicationDataLayer->getEncryptedDataLen();
                const uint64_t completeTLSLen = applicationDataLayer->getHeaderLen();

                LOG_TRACE << "applicationDataLayer->getEncryptedDataLen(): " << applicationDataLayer->getEncryptedDataLen();
                LOG_TRACE << "applicationDataLayer->getHeaderLen(): " << applicationDataLayer->getHeaderLen();

                const uint64_t bytesBeforeEncryptedData = completeTLSLen - encryptedDataLen;
                LOG_TRACE << "bytesBeforeEncryptedData: " << bytesBeforeEncryptedData;

                //create tls application file
                //TODO: does client always send first?
                if (!resultPtr) {
                    if (handshakeData->tlsVersion == 0)
                        // possible that extraction of tlsVersion was not done in advance
                        handshakeData->tlsVersion = sslLayer->getRecordVersion().asUInt();

                    resultPtr = std::make_shared<TlsFile>();
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
                        if (resultPtr->flags.test(flags::HAS_DECRYPTION_KEY))
                            resultPtr->setFilesizeProcessed(resultPtr->filesizeProcessed + resultPtr->calculateProcessedSize(idx));
                        else
                            resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());
                        visitedVirtualTlsFile = true;
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

                // if size is a mismatch => tls packet is malformed
                // TODO: Better detection of malformed tls packets
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

                offset += completeTLSLen;

                resultPtr->setFilesizeRaw(resultPtr->getFilesizeRaw() + encryptedDataLen);

				LOG_DEBUG << "Full TLS File afterwards:\n" << resultPtr->toString();

			} else if (recType == pcpp::SSL_ALERT) {
                const pcpp::SSLAlertLayer *alertLayer =
                        dynamic_cast<pcpp::SSLAlertLayer *>(sslLayer);
                offset += alertLayer->getHeaderLen();
            }

            sslLayer->parseNextLayer();
            sslLayer = dynamic_cast<pcpp::SSLLayer *>(sslLayer->getNextLayer());

            /*
             * If this is our last iteration we update the filesizeProcessed again
             * TODO: make this last step the only step to reduce duplicate decryption.
             * Idea: Just one decryption after all ciphertext is available. We need to keep track
             * of all connection breaks and package breaks. Then we can reconstruct it here inside the parser.
             */
            if(!sslLayer && visitedVirtualTlsFile && resultPtr->flags.test(flags::PROCESSED)) {
                LOG_DEBUG << "Fixing the fileSizeProcessed, setting it to the full size of plaintext.";
                const size_t calculated_size = resultPtr->calculateProcessedSize(idx);
                /*
                 * calculated_size contains all plain text in this context, therefore we do not need to add the current filesizeProcessed.
                 */
                LOG_DEBUG << "filesizeprocessed: " << calculated_size;
                resultPtr->setFilesizeProcessed(calculated_size);
            }
        }
    }

    //TODO: multiple tls streams in one tcp stream?!
    if (resultPtr) {
        resultVector.push_back(resultPtr);
    }

    std::copy(handshakeData->certificates.begin(), handshakeData->certificates.end(),
                std::back_inserter(resultVector));

    return resultVector;
}


//Returns the correct Master Secret out of a bunch of candidates
pcapfs::Bytes const pcapfs::TlsFile::searchCorrectMasterSecret(const TLSHandshakeDataPtr &handshakeData, const Index &idx) {

    bool isRsaKeyX = (handshakeData->cipherSuite->getKeyExchangeAlg() == pcpp::SSL_KEYX_RSA);
    const std::vector<pcapfs::FilePtr> keyFiles = idx.getCandidatesOfType("tlskey");

    for (const auto &keyFile: keyFiles) {
        const std::shared_ptr<TLSKeyFile> tlsKeyFile = std::dynamic_pointer_cast<TLSKeyFile>(keyFile);
        if (!tlsKeyFile) {
            LOG_ERROR << "dynamic_pointer_cast failed for tls key file";
            continue;
        }
        if (tlsKeyFile->getClientRandom().size() != 0 && tlsKeyFile->getClientRandom() == handshakeData->clientRandom){
            return tlsKeyFile->getMasterSecret();
        } else if (isRsaKeyX) {
            if (tlsKeyFile->getRsaIdentifier().size() != 0 && tlsKeyFile->getRsaIdentifier() == handshakeData->rsaIdentifier) {
                return crypto::createKeyMaterial(tlsKeyFile->getPreMasterSecret(), handshakeData, true);
            } else if (crypto::matchPrivateKey(tlsKeyFile->getRsaPrivateKey(), handshakeData->serverCertificate)) {
                return crypto::createKeyMaterial(crypto::rsaPrivateDecrypt(handshakeData->encryptedPremasterSecret,
                                                tlsKeyFile->getRsaPrivateKey(), true), handshakeData, true);
            }
        }
    }
    return Bytes();
}


int pcapfs::TlsFile::decryptData(const CiphertextPtr &input, Bytes &output) {

	const pcpp::SSLCipherSuite *cipher = pcpp::SSLCipherSuite::getCipherSuiteByName(cipherSuite);
    if (!cipher)
        return 1;

    switch (cipher->getSymKeyAlg()) {
        case pcpp::SSL_SYM_RC4_128:
        {
            crypto::decrypt_RC4_128(input, output, cipher->getMACAlg());
            break;
        }
        case pcpp::SSL_SYM_AES_128_CBC:
        {
            crypto::decrypt_AES_CBC(input, output, cipher->getMACAlg(), 16);
            break;
        }
        case pcpp::SSL_SYM_AES_256_CBC:
        {
            crypto::decrypt_AES_CBC(input, output, cipher->getMACAlg(), 32);
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
            LOG_ERROR << "unsupported encryption found in tls cipher suite: " << cipher->asString();
            return 0;
    }
    return 1;
}


size_t pcapfs::TlsFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

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


size_t pcapfs::TlsFile::readCertificate(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    std::string pemString = crypto::convertToPem(rawData);
    size_t readCount = std::min((size_t) pemString.length() - startOffset, length);
    memcpy(buf, pemString.c_str() + startOffset, length);
    return readCount;
}


size_t pcapfs::TlsFile::readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
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
        posInFragment = fragments.at(fragment).length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    while (position < startOffset + length && fragment < fragments.size()) {
        const size_t toRead = std::min(fragments.at(fragment).length - posInFragment, length - (position - startOffset));

        const pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
        filePtr->read(fragments.at(fragment).start + posInFragment, toRead, idx, buf + (position - startOffset));

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


size_t pcapfs::TlsFile::readDecryptedContent(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

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
        posInFragment = result.at(fragment).size() - (position - startOffset);
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
        const size_t toRead = std::min(result.at(fragment).size() - posInFragment, length - (position - startOffset));
        if(first_iteration) {
            bytes_ref = result.at(fragment);
            bytes_ref.erase(bytes_ref.begin(), bytes_ref.begin() + posInFragment);
            first_iteration = false;
        } else {
            bytes_ref = result.at(fragment);
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
size_t pcapfs::TlsFile::getFullCipherText(const Index &idx, std::vector<CiphertextPtr> &outputCipherTextVector) {
    size_t fragment = 0;
    size_t position = 0;
    int counter = 0;

    while (fragment < fragments.size()) {
        counter++;
        const size_t toRead = fragments.at(fragment).length;

        //TODO: is start=0 really good for missing data?
        // -> missing data should probably be handled in an exception?

        if (fragments.at(fragment).start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            LOG_INFO << "We have some missing TCP data: pcapfs::flags::MISSING_DATA was set";
        } else {
            // Read the bytes from the packets of the file (using the file pointer)
            const pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
            pcapfs::Bytes toDecrypt(this->fragments.at(fragment).length);
            filePtr->read(fragments.at(fragment).start, fragments.at(fragment).length, idx, (char *) toDecrypt.data());

            if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {

                std::shared_ptr<TLSKeyFile> keyPtr = std::dynamic_pointer_cast<TLSKeyFile>(
                    idx.get({"tlskey", getKeyIDinIndex()}));

                CiphertextPtr cte = std::make_shared<CipherTextElement>();
                cte->setVirtualFileOffset(previousBytes.at(fragment));
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
                const size_t counter_for_bytes_output_ciphertext = std::accumulate(outputCipherTextVector.begin(), outputCipherTextVector.end(), 0,
                                                        [](size_t counter, auto elem){ return counter + elem->getLength(); });
                const size_t counter_for_fragments = std::accumulate(fragments.begin(), fragments.end(), 0,
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
void pcapfs::TlsFile::decryptCiphertextVecToPlaintextVec(
		const std::vector<CiphertextPtr> &cipherTextVector,
		std::vector<Bytes> &outputPlainTextVector) {

    const pcpp::SSLCipherSuite *cipher = pcpp::SSLCipherSuite::getCipherSuiteByName(cipherSuite);
    if (!cipher) {
        LOG_ERROR << "invalid cipher suite: " << cipherSuite;
        // set ciphertext as output
        std::transform(cipherTextVector.begin(), cipherTextVector.end(), std::back_inserter(outputPlainTextVector),
                        [](auto &elem){ return elem->getCipherBlock(); });
        return;
    }

    // for cipher suites with RC4 we need to load the openssl legacy provider
    if (cipher->getSymKeyAlg() == pcpp::SSL_SYM_RC4_128)
        crypto::loadLegacyProvider();

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


bool pcapfs::TlsFile::isClientMessage(uint64_t i) {
    if (i % 2 == 0) {
        return true;
    } else {
        return false;
    }
}


bool pcapfs::TlsFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("tls", pcapfs::TlsFile::create, pcapfs::TlsFile::parse);


void pcapfs::TlsFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << cipherSuite;
    archive << tlsVersion;
    archive << (encryptThenMacEnabled ? 1 : 0);
    archive << (truncatedHmacEnabled ? 1 : 0);
    archive << keyIDinIndex;
    archive << previousBytes;
    archive << keyForFragment;
}


void pcapfs::TlsFile::deserialize(boost::archive::text_iarchive &archive) {
    int i, j = 0;
    VirtualFile::deserialize(archive);
    archive >> cipherSuite;
    archive >> tlsVersion;
    archive >> i;
    encryptThenMacEnabled = i ? true : false;
    archive >> j;
    truncatedHmacEnabled = j ? true : false;
    archive >> keyIDinIndex;
    archive >> previousBytes;
    archive >> keyForFragment;
}
