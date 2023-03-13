#include "udp.h"

#include <arpa/inet.h>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/ProtocolType.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

#include <chrono>

#include "../commontypes.h"
#include "../logging.h"
#include "../filefactory.h"
#include "../utils.h"
#include "../capturefiles/pcap.h"


using namespace pcpp;


namespace {

    struct UdpIndexerState {
        std::unordered_map<std::string, std::shared_ptr<pcapfs::UdpFile>> files;
        Fragment currentOffset;
        size_t nextUniqueId = 0;
        uint64_t currentPcapfileID;
        pcapfs::TimePoint currentTimestamp;
    };

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
        posInFragment = fragments[fragment].length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    // start copying
    while (position < startOffset + length && fragment < fragments.size()) {
        size_t toRead = std::min(fragments[fragment].length - posInFragment, length - (position - startOffset));

        //TODO: is start=0 really good for missing data?
        if (fragments[fragment].start == 0) {
            // TCP missing data
            memset(buf + (position - startOffset), 0, toRead);
        } else {
            //TODO: offsets at which number?
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragment).id});
            filePtr->read(fragments[fragment].start + posInFragment, toRead, idx, buf + (position - startOffset));
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


std::vector<pcapfs::FilePtr> pcapfs::UdpFile::createUDPVirtualFilesFromPcaps(
        const std::vector<pcapfs::FilePtr> &pcapFiles) {

    std::vector<pcapfs::FilePtr> result{};
    UdpIndexerState state{};
    PcapPtr pcapPtr;

    for (auto &pcap: pcapFiles) {
        pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapFile>(pcap);
        state.currentPcapfileID = pcap->getIdInIndex();
        std::shared_ptr<pcpp::IFileReaderDevice> reader = pcapPtr->getReader();

        RawPacket rawPacket;
        size_t pcapPosition = pcapPtr->getGlobalHeaderLen();

        for (size_t i = 1; reader->getNextPacket(rawPacket); i++) {

            Packet parsedPacket = Packet(&rawPacket);
            state.currentTimestamp = utils::convertTimeValToTimePoint(rawPacket.getPacketTimeStamp());

            pcapPosition += pcapPtr->getPacketHeaderLen();

            if (parsedPacket.isPacketOfType(pcpp::UDP) && parsedPacket.isPacketOfType(IP)) {
                std::shared_ptr<pcapfs::UdpFile> udpPointer;

                state.currentOffset.id = state.currentPcapfileID;
                state.currentOffset.start = pcapPosition;
                Layer *l = parsedPacket.getFirstLayer();//->getDataLen();
                state.currentOffset.start += l->getHeaderLen();
                while (l->getProtocol() != pcpp::UDP) {
                    l = l->getNextLayer();
                    state.currentOffset.start += l->getHeaderLen();
                }
                UdpLayer *udpLayer = parsedPacket.getLayerOfType<UdpLayer>();
                state.currentOffset.length = udpLayer->getDataLen();

                std::string conString = "";
                //TODO: put that in a helper function


                if (parsedPacket.isPacketOfType(IPv4)) {
                    IPv4Layer *iPv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
                    conString += iPv4Layer->getSrcIPv4Address().toString();
                    conString += iPv4Layer->getDstIPv4Address().toString();
                } else if (parsedPacket.isPacketOfType(IPv6)) {
                    IPv6Layer *iPv6Layer = parsedPacket.getLayerOfType<IPv6Layer>();
                    conString += iPv6Layer->getSrcIPv6Address().toString();
                    conString += iPv6Layer->getDstIPv6Address().toString();
                }

                conString += std::to_string(ntohs(udpLayer->getUdpHeader()->portSrc));
                conString += std::to_string(ntohs(udpLayer->getUdpHeader()->portDst));

                //TODO: create a new "udp stream" after a certain amount of time
                if (state.files.count(conString) == 1) {
                    state.files[conString]->fragments.push_back(state.currentOffset);
                } else {

                    // create a new fileinformation
                    state.files.emplace(conString, std::make_shared<pcapfs::UdpFile>());
                    udpPointer = state.files[conString];

                    udpPointer->setFirstPacketNumber(i);
                    udpPointer->setTimestamp(state.currentTimestamp);
                    udpPointer->setFilename("UDPFILE" + std::to_string(state.nextUniqueId));
                    udpPointer->setIdInIndex(state.nextUniqueId);
                    udpPointer->setOffsetType("pcap"); //udp files point directly into the pcap
                    udpPointer->setFilesizeRaw(udpLayer->getDataLen());
                    udpPointer->setFilesizeProcessed(udpLayer->getDataLen());
                    udpPointer->setFiletype("udp");

                    if (parsedPacket.isPacketOfType(IPv4)) {
                        IPv4Layer *iPv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
                        udpPointer->setProperty("srcIP", iPv4Layer->getSrcIPv4Address().toString());
                        udpPointer->setProperty("dstIP", iPv4Layer->getDstIPv4Address().toString());
                    } else if (parsedPacket.isPacketOfType(IPv6)) {
                        IPv6Layer *iPv6Layer = parsedPacket.getLayerOfType<IPv6Layer>();
                        udpPointer->setProperty("srcIP", iPv6Layer->getSrcIPv6Address().toString());
                        udpPointer->setProperty("dstIP", iPv6Layer->getDstIPv6Address().toString());
                    }

                    udpPointer->setProperty("srcPort", std::to_string(ntohs(udpLayer->getUdpHeader()->portSrc)));
                    udpPointer->setProperty("dstPort", std::to_string(ntohs(udpLayer->getUdpHeader()->portDst)));
                    udpPointer->setProperty("protocol", "udp");
                    udpPointer->fragments.push_back(state.currentOffset);
                    ++state.nextUniqueId;
                }
            }
            pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
        }
        pcapPtr->closeReader();
    }
    //TODO: add connection breaks for udp
    // Add all streams that are not closed (still in state.files map) to the result vector
    std::transform(state.files.begin(), state.files.end(), std::back_inserter(result),
                    [](auto &f){ return std::static_pointer_cast<pcapfs::File>(f.second); });
    return result;
}


bool pcapfs::UdpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("udp", pcapfs::UdpFile::create);
