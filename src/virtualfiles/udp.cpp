#include "udp.h"

#include <arpa/inet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
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
        SimpleOffset currentOffset;
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
        /*if (!pcapfs::CONF.zero_padding && offsets[fragment].start == 0) {
            LOG_TRACE << "Skipping zero padded data";
            fragment++;
            continue;
        }*/

        size_t toRead = std::min(offsets[fragment].length - posInFragment, length - (position - startOffset));

        //TODO: is start=0 really good for missing data?
        if (offsets[fragment].start == 0) {
            // TCP missing data
            memset(buf + (position - startOffset), 0, toRead);
            //LOG_ERROR << "filling data";
        } else {
            //TODO: offsets at which number?
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->offsets.at(fragment).id});
            filePtr->read(offsets[fragment].start + posInFragment, toRead, idx, buf + (position - startOffset));
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

            if (parsedPacket.isPacketOfType(ProtocolType::UDP) && parsedPacket.isPacketOfType(IP)) {
                std::shared_ptr<pcapfs::UdpFile> udpPointer;

                //LOG_ERROR << "Found UDP packet, packet number: " << i;
                state.currentOffset.id = state.currentPcapfileID;
                state.currentOffset.start = pcapPosition;
                Layer *l = parsedPacket.getFirstLayer();//->getDataLen();
                state.currentOffset.start += l->getHeaderLen();
                while (l->getProtocol() != ProtocolType::UDP) {
                    l = l->getNextLayer();
                    state.currentOffset.start += l->getHeaderLen();
                }
                UdpLayer *udpLayer = parsedPacket.getLayerOfType<UdpLayer>();
                //state.currentOffset.length = tcp::calc_ip_payload(parsedPacket) - udpLayer->getHeaderLen();
                state.currentOffset.length = udpLayer->getDataLen();

                std::string conString = "";
                //TODO: put that in a helper function


                if (parsedPacket.isPacketOfType(IPv4)) {
                    IPv4Layer *iPv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
                    conString += iPv4Layer->getSrcIpAddress().toString();
                    conString += iPv4Layer->getDstIpAddress().toString();
                } else if (parsedPacket.isPacketOfType(IPv6)) {
                    IPv6Layer *iPv6Layer = parsedPacket.getLayerOfType<IPv6Layer>();
                    conString += iPv6Layer->getSrcIpAddress().toString();
                    conString += iPv6Layer->getDstIpAddress().toString();
                }

                conString += std::to_string(ntohs(udpLayer->getUdpHeader()->portSrc));
                conString += std::to_string(ntohs(udpLayer->getUdpHeader()->portDst));

                //TODO: create a new "udp stream" after a certain amount of time
                if (state.files.count(conString) == 1) {
                    state.files[conString]->offsets.push_back(state.currentOffset);
                } else {
                    /*pcapfs::protocols::HTTP::reverseConnMeta(udpc.conn);
                    if( state.files.count(udpc) == 1 ) {
                        // udp "stream" goes the other direction, finish up the old one
                        IndexFileInformation *to_finish = state.files[udpc];
                        result.push_back(*to_finish);
                        state.files.erase(udpc);
                        delete to_finish;
                        pcapfs::protocols::HTTP::reverseConnMeta(udpc.conn);
                    }*/

                    // create a new fileinformation
                    state.files.emplace(conString, std::make_shared<pcapfs::UdpFile>());
                    udpPointer = state.files[conString];

                    udpPointer->setFirstPacketNumber(i);
                    //tcp_file->fileinformation.flags = 0;
                    udpPointer->setTimestamp(state.currentTimestamp);
                    udpPointer->setFilename("UDPFILE" + std::to_string(state.nextUniqueId));
                    udpPointer->setIdInIndex(state.nextUniqueId);
                    udpPointer->setOffsetType("pcap"); //udp files point directly into the pcap
                    udpPointer->setFilesizeRaw(udpLayer->getDataLen());
                    udpPointer->setFiletype("udp");
                    //tcp_file->fileinformation.filesize_uncompressed = tcpData.getDataLength();
                    //udpPointer->connectionBreaks.push_back({0, state.currentTimestamp});

                    if (parsedPacket.isPacketOfType(IPv4)) {
                        IPv4Layer *iPv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
                        udpPointer->setProperty("srcIP", iPv4Layer->getSrcIpAddress().toString());
                        udpPointer->setProperty("dstIP", iPv4Layer->getDstIpAddress().toString());
                    } else if (parsedPacket.isPacketOfType(IPv6)) {
                        IPv6Layer *iPv6Layer = parsedPacket.getLayerOfType<IPv6Layer>();
                        udpPointer->setProperty("srcIP", iPv6Layer->getSrcIpAddress().toString());
                        udpPointer->setProperty("dstIP", iPv6Layer->getDstIpAddress().toString());
                    }

                    udpPointer->setProperty("srcPort", std::to_string(ntohs(udpLayer->getUdpHeader()->portSrc)));
                    udpPointer->setProperty("dstPort", std::to_string(ntohs(udpLayer->getUdpHeader()->portDst)));
                    udpPointer->setProperty("protocol", "udp");
                    udpPointer->offsets.push_back(state.currentOffset);
                    ++state.nextUniqueId;

                    /*IndexFileInformation * file_template = new IndexFileInformation();
                    pcapfs::protocols::HTTP::initConnMeta(udpc.conn, file_template->conn);
                    file_template->offsets.push_back(state.currentOffset);
                    file_template->flow_ID = state.nextUniqueId;
                    file_template->firstPacketNumber = i;
                    file_template->timestamp = rawPacket.getPacketTimeStamp().tv_sec;
                    file_template->flags = 0;
                    file_template->offsetType = pcapfs::index::fileType::pcap;
                    file_template->filename = "";
                    file_template->protocolType = "udp";

                    state.files[udpc] = file_template;*/
                }
            }
            pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
        }
        pcapPtr->closeReader();
    }
    //TODO: add connection breaks for udp
    // Add all streams that are not closed (still in state.files map) to the result vector
    for (auto &f : state.files) {
        result.push_back(std::static_pointer_cast<pcapfs::File>(f.second));
    }
    return result;
}


bool pcapfs::UdpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("udp", pcapfs::UdpFile::create);