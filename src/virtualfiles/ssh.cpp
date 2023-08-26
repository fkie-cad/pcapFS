#include "ssh.h"
#include "../filefactory.h"
#include "../crypto/cryptutils.h"
#include <numeric>
#include <boost/algorithm/string.hpp>
#include <pcapplusplus/SSHLayer.h>


std::vector<pcapfs::FilePtr> pcapfs::SshFile::parse(pcapfs::FilePtr filePtr, pcapfs::Index &idx) {
    (void)idx; 
    std::vector<FilePtr> resultVector(0);
    if(!isSshTraffic(filePtr)){
        return resultVector;
    }

    LOG_TRACE << "starting SSH parser";
    const Bytes data = filePtr->getBuffer();
    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();

    Bytes kexInitFragments(0);
    size_t kexInitMsgLen = 0;
    bool oddKexInitMsgCompleted = false;
    bool handshakeCompleted = false;
    bool clientBeginsConnection = false;

    // With our means, we cannot determine, whether client or server sends the first SSH packet, before the SSH_MSG_KEX_DH_(GEX)_INIT message
    // which is always sent by the client
    // Thus, we need to calculate hashh and hasshServer for both SSH_MSG_KEXINIT messages. At the end, when it is clear whether client or server
    // sent the first SSH packet, we choose the correct value.
    // Every variable with postfix "Even" correlates to data sent by the side which sent the first SSH packet and 
    // every variable with postfix "Odd" correlates to data sent by the responding side.
    std::string hasshServerOdd;
    std::string hasshOdd;
    std::string hasshServerEven;
    std::string hasshEven;

    std::shared_ptr<SshFile> resultPtr = std::make_shared<SshFile>();

    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = filePtr->connectionBreaks.at(i).first;
        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        pcpp::SSHLayer *sshLayer = pcpp::SSHLayer::createSSHMessage((uint8_t *) data.data() + offset, size, nullptr, nullptr);

        while (sshLayer) {
            if (memcmp(sshLayer->getData(), "SSH-", 4) == 0) {
                LOG_TRACE << "found identification message";
                if (isOdd(i)) {
                    const size_t oddIdentMsgLen = getLenOfIdentMsg(sshLayer);
                    if (oddIdentMsgLen < sshLayer->getDataLen()) {
                        LOG_TRACE << " (first part of) SSH_MSG_KEXINIT message from server comes directly after identification string";
                        kexInitFragments.insert(kexInitFragments.end(), sshLayer->getData()+oddIdentMsgLen, sshLayer->getData()+sshLayer->getDataLen());
                        kexInitMsgLen = be32toh(*(uint32_t*) (sshLayer->getData()+oddIdentMsgLen)) + 4 ; // +4 for length field                    
                    }
                }

            } else {
                // no identification message
                const pcpp::SSHHandshakeMessage* tempSshHandshakeMessage = dynamic_cast<pcpp::SSHHandshakeMessage*>(sshLayer);
                if (tempSshHandshakeMessage && (tempSshHandshakeMessage->getMessageType() == pcpp::SSHHandshakeMessage::SSH_MSG_KEX_DH_INIT ||
                                            tempSshHandshakeMessage->getMessageType() == pcpp::SSHHandshakeMessage::SSH_MSG_KEX_DH_GEX_INIT)) {
                    clientBeginsConnection = !isOdd(i);

                } else if (isOdd(i)) {
                    if (!oddKexInitMsgCompleted) {
                        const pcpp::SSHHandshakeMessage* sshHandshakeMessage = dynamic_cast<pcpp::SSHHandshakeMessage*>(sshLayer);
                        if (sshHandshakeMessage && sshHandshakeMessage->getMessageType() == pcpp::SSHHandshakeMessage::SSH_MSG_KEX_INIT) {
                            pcpp::SSHKeyExchangeInitMessage* oddKexInitMsg = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(sshLayer);
                            if (!oddKexInitMsg)
                                continue;
                            // SSH_MSG_KEXINIT message is complete and not fragmented
                            LOG_TRACE << "found complete SSH_MSG_KEX_INIT message";
                            hasshServerOdd = computeHasshServer(oddKexInitMsg);
                            hasshOdd = computeHassh(oddKexInitMsg);
                            LOG_TRACE << "computed fingerprints for odd side:";
                            LOG_TRACE << "hassh: " << hasshOdd;
                            LOG_TRACE << "hasshServer: " << hasshServerOdd;
                            oddKexInitMsgCompleted = true;
                            
                        } else {
                            if (sshLayer->getDataLen() >=  kexInitMsgLen - kexInitFragments.size() && kexInitMsgLen != 0) {
                                LOG_TRACE << "detected end of fragmented SSH_MSG_KEXINIT message";
                                // we have the last part of the fragmented server kex init message but maybe also
                                // a first chunk of the following (diffie-hellman) kex message
                                kexInitFragments.insert(kexInitFragments.end(), sshLayer->getData(),
                                                                sshLayer->getData()+kexInitMsgLen-kexInitFragments.size());
                                
                                pcpp::SSHLayer *defragmentedSshLayer = pcpp::SSHLayer::createSSHMessage((uint8_t *) kexInitFragments.data(),
                                                                                                        kexInitFragments.size(), nullptr, nullptr);
                                if (!defragmentedSshLayer)
                                    continue;

                                pcpp::SSHKeyExchangeInitMessage* defragmentedOddKexInitMsg = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(defragmentedSshLayer);
                                if (!defragmentedOddKexInitMsg)
                                    continue;
                                hasshServerOdd = computeHasshServer(defragmentedOddKexInitMsg);
                                hasshOdd = computeHassh(defragmentedOddKexInitMsg);
                                LOG_TRACE << "computed fingerprints for odd side from fragmented SSH_MSG_KEXINIT message:";
                                LOG_TRACE << "hassh: " << hasshOdd;
                                LOG_TRACE << "hasshServer: " << hasshServerOdd;
                                oddKexInitMsgCompleted = true;

                            } else {
                                // SSH_MSG_KEXINIT message still not fully consumed by our fragments buffer
                                kexInitFragments.insert(kexInitFragments.end(), sshLayer->getData(), sshLayer->getData()+sshLayer->getDataLen());
                            }
                        }
                    
                    } else if (!handshakeCompleted) {
                        // we have passed SSH_MSG_KEXINIT message from odd side but handshake is not finished yet
                        const pcpp::SSHHandshakeMessage* sshHandshakeMessage = dynamic_cast<pcpp::SSHHandshakeMessage*>(sshLayer);
                        if (sshHandshakeMessage && sshHandshakeMessage->getMessageType() == pcpp::SSHHandshakeMessage::SSH_MSG_NEW_KEYS) {
                            LOG_TRACE << "found SSH_MSG_NEWKEYS sent by odd side -> handshake completed";
                            handshakeCompleted = true;
                        }

                    } else {
                        // handshake is completely finished
                        const pcpp::SSHEncryptedMessage* encryptedMessage = dynamic_cast<pcpp::SSHEncryptedMessage*>(sshLayer);
                        if (encryptedMessage) {
                            Fragment fragment;
                            fragment.id = filePtr->getIdInIndex();
                            fragment.start = offset;
                            fragment.length = encryptedMessage->getDataLen();
                            resultPtr->fragments.push_back(fragment);
                        }
                    }
                        
                } else {
                    const pcpp::SSHHandshakeMessage* sshHandshakeMessage = dynamic_cast<pcpp::SSHHandshakeMessage*>(sshLayer);
                    if (sshHandshakeMessage && sshHandshakeMessage->getMessageType() == pcpp::SSHHandshakeMessage::SSH_MSG_KEX_INIT) {
                        pcpp::SSHKeyExchangeInitMessage* evenKexInitMsg = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(sshLayer);
                        if (!evenKexInitMsg)
                            continue;
                        // SSH_MSG_KEXINIT message is complete and not fragmented
                        LOG_TRACE << "found complete SSH_MSG_KEX_INIT message";
                        hasshEven = computeHassh(evenKexInitMsg);
                        hasshServerEven = computeHasshServer(evenKexInitMsg);
                        LOG_TRACE << "computed fingerprints for even side:";
                        LOG_TRACE << "hassh: " << hasshEven;
                        LOG_TRACE << "hasshServer: " << hasshServerEven;

                    } else if (handshakeCompleted) {
                        const pcpp::SSHEncryptedMessage* encryptedMessage = dynamic_cast<pcpp::SSHEncryptedMessage*>(sshLayer);
                        if (encryptedMessage) {
                            Fragment fragment;
                            fragment.id = filePtr->getIdInIndex();
                            fragment.start = offset;
                            fragment.length = encryptedMessage->getDataLen();
                            resultPtr->fragments.push_back(fragment);
                        }
                    }
                }
            }
            
            sshLayer->parseNextLayer();
            offset += sshLayer->getHeaderLen();
            sshLayer = dynamic_cast<pcpp::SSHLayer*>(sshLayer->getNextLayer());
        }
    }

    if (resultPtr->fragments.empty())
        return resultVector;

    const size_t filesize = std::accumulate(resultPtr->fragments.begin(), resultPtr->fragments.end(), 0,
                                                        [](size_t counter, Fragment frag){ return counter + frag.length; });
    resultPtr->flags.set(pcapfs::flags::PROCESSED);
    resultPtr->setFilesizeRaw(filesize);
    resultPtr->setFilesizeProcessed(filesize);

    resultPtr->setTimestamp(filePtr->connectionBreaks.at(0).second);
    resultPtr->setFilename("SSH");
    resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    resultPtr->setOffsetType(filePtr->getFiletype());
    resultPtr->setFiletype("ssh");
    resultPtr->setProperty("protocol", "ssh");

    if (clientBeginsConnection) {
        if (!hasshEven.empty())
            resultPtr->setProperty("hassh", hasshEven);
        if (!hasshServerEven.empty())
            resultPtr->setProperty("hasshServer", hasshServerOdd);
    } else {
        if (!hasshOdd.empty())
            resultPtr->setProperty("hassh", hasshOdd);
        if (!hasshServerOdd.empty())
            resultPtr->setProperty("hasshServer", hasshServerEven);
    }

    resultVector.push_back(resultPtr);
    return resultVector;
}


bool pcapfs::SshFile::isSshTraffic(const FilePtr &filePtr) {
    return filePtr->getProperty("dstPort") == "22" || filePtr->getProperty("srcPort") == "22";
}


bool pcapfs::SshFile::isOdd(uint64_t i) {
    if (i % 2 == 0)
        return false;
    else
        return true;
}


size_t pcapfs::SshFile::getLenOfIdentMsg(pcpp::SSHLayer *sshLayer) {
    const Bytes temp(sshLayer->getData(), sshLayer->getData()+sshLayer->getDataLen());
    const auto it = std::find_if(temp.begin(), temp.end(), [](unsigned char c){ return c == 0xa; });
    return std::distance(temp.begin(), it) + 1;
}


std::string const pcapfs::SshFile::computeHassh(pcpp::SSHKeyExchangeInitMessage* clientKexInitMsg) {
    std::stringstream ss;
    ss << clientKexInitMsg->getKeyExchangeAlgorithms() << ";" << clientKexInitMsg->getEncryptionAlgorithmsClientToServer()
        << ";" << clientKexInitMsg->getMacAlgorithmsClientToServer() << ";" << clientKexInitMsg->getCompressionAlgorithmsClientToServer();
    return crypto::calculateMD5(ss.str());
}


std::string const pcapfs::SshFile::computeHasshServer(pcpp::SSHKeyExchangeInitMessage* serverKexInitMsg) {
    std::stringstream ss;
    ss << serverKexInitMsg->getKeyExchangeAlgorithms() << ";" << serverKexInitMsg->getEncryptionAlgorithmsClientToServer()
        << ";" << serverKexInitMsg->getMacAlgorithmsClientToServer() << ";" << serverKexInitMsg->getCompressionAlgorithmsClientToServer();
    return crypto::calculateMD5(ss.str());
}


size_t pcapfs::SshFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes totalContent;
    for (Fragment fragment: fragments) {
        Bytes rawData(fragment.length);
        FilePtr filePtr = idx.get({offsetType, fragment.id});
        filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
        totalContent.insert(totalContent.end(), rawData.begin(), rawData.end());
    }
    memcpy(buf, totalContent.data() + startOffset, length);
    return std::min(totalContent.size() - startOffset, length);
}


bool pcapfs::SshFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ssh", pcapfs::SshFile::create, pcapfs::SshFile::parse);