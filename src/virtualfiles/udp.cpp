#include "udp.h"

#include <chrono>
#include <arpa/inet.h>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>

#include "../commontypes.h"
#include "../logging.h"
#include "../filefactory.h"
#include "../utils.h"
#include "../capturefiles/pcap.h"
#include "../capturefiles/pcapng.h"


pcapfs::UdpConnection::UdpConnection(const pcpp::Packet &packet, const TimePoint &timestamp, const std::string &fileType, uint64_t pcapID) {
    if (packet.isPacketOfType(pcpp::IPv4)) {
        const pcpp::IPv4Layer *ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
        endpoint1.ipAddress = ipv4Layer->getSrcIPv4Address().toString();
        endpoint2.ipAddress = ipv4Layer->getDstIPv4Address().toString();
    } else if (packet.isPacketOfType(pcpp::IPv6)) {
        const pcpp::IPv6Layer *ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
        endpoint1.ipAddress = ipv6Layer->getSrcIPv6Address().toString();
        endpoint2.ipAddress = ipv6Layer->getDstIPv6Address().toString();
    }

    const pcpp::UdpLayer *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    endpoint1.port = ntohs(udpLayer->getUdpHeader()->portSrc);
    endpoint2.port = ntohs(udpLayer->getUdpHeader()->portDst);
    startTime = timestamp;
    streamsToEndpoint1 = false;
    captureFileType = fileType;
    captureFileId = pcapID;
}


bool pcapfs::UdpConnection::directionChanged(const UdpConnection &conn) {
    if (streamsToEndpoint1)
        if (conn.endpoint1 == endpoint1 && conn.endpoint2 == endpoint2) {
            return true;
        } else
            return false;
    else {
        if (conn.endpoint1 == endpoint2 && conn.endpoint2 == endpoint1) {
            return true;
        } else
            return false;
    }
}


size_t pcapfs::UdpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    size_t fragment = 0;
    size_t posInFragment = 0;
    size_t position = 0;

    // seek to start_offset
    while (position < startOffset) {
        position += fragments[fragment].length;
        fragment++;
    }

    if (position > startOffset) {
        fragment--;
        posInFragment = fragments.at(fragment).length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    // start copying
    while (position < startOffset + length && fragment < fragments.size()) {
        const size_t toRead = std::min(fragments.at(fragment).length - posInFragment, length - (position - startOffset));
        pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
        filePtr->read(fragments.at(fragment).start + posInFragment, toRead, idx, buf + (position - startOffset));

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


std::vector<pcapfs::FilePtr> pcapfs::UdpFile::createUDPVirtualFilesFromPcaps(
        const std::vector<pcapfs::FilePtr> &pcapFiles) {

    std::vector<pcapfs::FilePtr> result{};
    UdpIndexerState state{};
    std::shared_ptr<CaptureFile> pcapPtr;
    LOG_TRACE << "start extracting UDP files";

    for (auto &pcap: pcapFiles) {
        if (pcap->getFiletype() == "pcap")
            pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapFile>(pcap);
        else
            pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapNgFile>(pcap);

        state.currentPcapfileID = pcap->getIdInIndex();
        std::shared_ptr<pcpp::IFileReaderDevice> reader = pcapPtr->getReader();

        pcpp::RawPacket rawPacket;
        size_t pcapPosition = pcapPtr->getOffsetFromLastBlock(0);

        for (size_t i = 1; reader->getNextPacket(rawPacket); i++) {

            const pcpp::Packet parsedPacket = pcpp::Packet(&rawPacket);
            state.currentTimestamp = utils::convertTimeValToTimePoint(rawPacket.getPacketTimeStamp());

            pcapPosition += pcapPtr->getOffsetFromLastBlock(i);

            if (parsedPacket.isPacketOfType(pcpp::UDP) && parsedPacket.isPacketOfType(pcpp::IP) && !parsedPacket.isPacketOfType(pcpp::ICMP)) {

                state.currentOffset.id = state.currentPcapfileID;
                state.currentOffset.start = pcapPosition;
                pcpp::Layer *l = parsedPacket.getFirstLayer();
                state.currentOffset.start += l->getHeaderLen();
                while (l->getProtocol() != pcpp::UDP) {
                    l = l->getNextLayer();
                    state.currentOffset.start += l->getHeaderLen();
                }
                const pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                if (udpLayer->getLayerPayloadSize() == 0) {
                    if (pcap->getFiletype() == "pcap")
                        pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
                    continue;
                }
                state.currentOffset.length = udpLayer->getLayerPayloadSize();

                const UdpConnection udpConn(parsedPacket, state.currentTimestamp, pcapPtr->getFiletype(), state.currentPcapfileID);
                const auto pos = std::find_if(state.files.begin(), state.files.end(), [udpConn](const auto &elem){ return elem.first == udpConn; });
                if (pos != state.files.end()) {
                    // packet is part of already known UDP "connection" and UDP payload is added as fragment to existing UDP file
                    LOG_TRACE << "add UDP packet payload to existing UDP file";
                    UdpConnection targetConn = pos->first;
                    state.files[targetConn]->fragments.push_back(state.currentOffset);
                    state.files[targetConn]->setFilesizeRaw(state.files[targetConn]->getFilesizeRaw() + udpLayer->getLayerPayloadSize());
                    state.files[targetConn]->setFilesizeProcessed(state.files[targetConn]->getFilesizeRaw());
                    if (targetConn.directionChanged(udpConn)) {
                        // direction of UDP packet changed -> add connection break
                        LOG_TRACE << "add new connection break";
                        pos->first.streamsToEndpoint1 = !pos->first.streamsToEndpoint1;
                        state.files[targetConn]->connectionBreaks.emplace_back(state.files[targetConn]->getFilesizeRaw() - udpLayer->getLayerPayloadSize(),
                                                                            state.currentTimestamp);
                    }
                } else {
                    // UDP packet does not match to existing UDP file -> create new one
                    LOG_TRACE << "creating new UDP file";
                    std::shared_ptr<pcapfs::UdpFile> udpPointer = std::make_shared<pcapfs::UdpFile>();
                    udpPointer->setFirstPacketNumber(i);
                    udpPointer->setTimestamp(state.currentTimestamp);
                    udpPointer->setFilename("udp" + std::to_string(state.nextUniqueId));
                    udpPointer->setIdInIndex(state.nextUniqueId);
                    udpPointer->setOffsetType(pcapPtr->getFiletype()); //udp files point directly into the pcap
                    udpPointer->setFilesizeRaw(udpLayer->getLayerPayloadSize());
                    udpPointer->setFilesizeProcessed(udpLayer->getLayerPayloadSize());
                    udpPointer->setFiletype("udp");

                    udpPointer->setProperty("srcIP", udpConn.endpoint1.ipAddress);
                    udpPointer->setProperty("dstIP", udpConn.endpoint2.ipAddress);
                    udpPointer->setProperty("srcPort", std::to_string(udpConn.endpoint1.port));
                    udpPointer->setProperty("dstPort", std::to_string(udpConn.endpoint2.port));

                    udpPointer->setProperty("protocol", "udp");
                    udpPointer->fragments.push_back(state.currentOffset);
                    udpPointer->connectionBreaks.emplace_back(0, state.currentTimestamp);
                    state.files.emplace(udpConn, udpPointer);
                    ++state.nextUniqueId;
                }
            }
            if (pcap->getFiletype() == "pcap")
                pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
        }
        pcapPtr->closeReader();
    }

    // Add all streams in state.files map to the result vector
    std::transform(state.files.begin(), state.files.end(), std::back_inserter(result),
                    [](auto &f){ return std::static_pointer_cast<pcapfs::File>(f.second); });
    LOG_TRACE << "finished with creating UDP files";
    return result;
}


bool pcapfs::UdpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("udp", pcapfs::UdpFile::create);
