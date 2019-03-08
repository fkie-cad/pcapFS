#include "tcp.h"

#include <netinet/in.h>
#include <string>
#include <vector>
#include <fstream>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>

#include "../dirlayout.h"
#include "../utils.h"
#include "../capturefiles/pcap.h"


size_t pcapfs::TcpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
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

    while (position < startOffset + length && fragment < offsets.size()) {
        size_t toRead = std::min(offsets[fragment].length - posInFragment, length - (position - startOffset));
        //TODO: is start=0 really good for missing data?
        if (offsets[fragment].start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            memset(buf + (position - startOffset), 0, toRead);
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

int pcapfs::TcpFile::calcIpPayload(pcpp::Packet &p) {
    if (p.isPacketOfType(pcpp::IPv4)) {
        pcpp::IPv4Layer *ip = p.getLayerOfType<pcpp::IPv4Layer>();
        if (ip == nullptr) {
            LOG_ERROR << p.toString();
            throw std::runtime_error("nullptr for ipv4 packet");
        }
        return ntohs(ip->getIPv4Header()->totalLength) - (int) ip->getHeaderLen();
    } else if (p.isPacketOfType(pcpp::IPv6)) {
        pcpp::IPv6Layer *ip = p.getLayerOfType<pcpp::IPv6Layer>();
        if (ip == nullptr) {
            LOG_ERROR << p.toString();
            throw std::runtime_error("nullptr for ipv6 packet");
        }
        return ntohs(ip->getIPv6Header()->payloadLength);
    }
    throw std::runtime_error("packet not ipv4 nor ipv6");
}

void pcapfs::TcpFile::messageReadycallback(int side, pcpp::TcpStreamData tcpData, void *userCookie) {
    TCPIndexerState *state = static_cast<pcapfs::TcpFile::TCPIndexerState *>(userCookie);
    //File_Offsets* tcp_file = (*files)[pair(tcpData.getConnectionData().flowKey, side)];

    uint32_t flowkey = tcpData.getConnectionData().flowKey;
    pcapfs::TcpFile::TCPPtr tcpPointer;

    if (tcpData.getDataLength() == 0) {
        LOG_TRACE << "Empty tcp Data";
    }

    if (state->files.find(flowkey) == state->files.end()) {
        LOG_TRACE << "New file with key: " << flowkey;

        /*if (!files.insert(std::pair<uint32_t, FileInformation *>(flowkey, tcp_file)).second) {
            LOG_ERROR << "Duplicate flowkey!";
            exit(666);
        }*/

        state->files.emplace(flowkey, std::make_shared<pcapfs::TcpFile>());
        state->currentSide.insert(std::pair<uint32_t, int>(flowkey, side));
        tcpPointer = state->files[flowkey];

        tcpPointer->setFirstPacketNumber(state->currentOffset.frameNr);
        //tcp_file->fileinformation.flags = 0;
        tcpPointer->setTimestamp(state->currentTimestamp);
        tcpPointer->setFilename("tcp" + std::to_string(state->nextUniqueId));
        tcpPointer->setIdInIndex(state->nextUniqueId);
        tcpPointer->setOffsetType("pcap"); //tcp files point directly into the pcap
        tcpPointer->setFilesizeRaw(tcpData.getDataLength());
        tcpPointer->setFiletype("tcp");
        //tcp_file->fileinformation.filesize_uncompressed = tcpData.getDataLength();
        tcpPointer->connectionBreaks.emplace_back(0, state->currentTimestamp);

        tcpPointer->setProperty("srcIP", tcpData.getConnectionData().srcIP->toString());
        tcpPointer->setProperty("dstIP", tcpData.getConnectionData().dstIP->toString());
        tcpPointer->setProperty("srcPort", std::to_string(tcpData.getConnectionData().srcPort));
        tcpPointer->setProperty("dstPort", std::to_string(tcpData.getConnectionData().dstPort));
        tcpPointer->setProperty("protocol", "tcp");
        ++state->nextUniqueId;
    } else {
        tcpPointer = state->files[flowkey];
        tcpPointer->setFilesizeRaw(tcpPointer->getFilesizeRaw() + tcpData.getDataLength());
        //TODO: where to add uncompressed/unprocessed filesize?
        //tcp_file->fileinformation.filesize_uncompressed += tcpData.getDataLength();
    }

    if (state->currentSide[flowkey] != side) {
        //curent filesize (without tcp data) equals the offset in tcp stream where break occured
        state->currentSide[flowkey] = side;
        tcpPointer->connectionBreaks.emplace_back(tcpPointer->getFilesizeRaw() - tcpData.getDataLength(),
                                                  state->currentTimestamp);

    }

    std::string datastr = std::string((char *) tcpData.getData(), tcpData.getDataLength());
    unsigned long missing_count = 0;
    unsigned long missing_str_len = 0;
    if (datastr.find("bytes missing]") != std::string::npos) {
        missing_str_len = datastr.find(']') + 1;
        sscanf((char *) tcpData.getData(), "[ %lu bytes missing]", &missing_count);
        LOG_TRACE << missing_count << " bytes of missing TCP-data found";
        /* Which side is the missing data?? -> The last side seen
         * What if missing data at start of stream? -> No information, assuming(!!) first side seen after
         * Is the missing data spread over several HTTP-messages or even sides?! -> Assuming no
         */
        SimpleOffset soff;
        //TODO: check for missing data

        if (!tcpPointer->offsets.empty()) {
            soff = tcpPointer->offsets.back();
        } else {
            //LOG_ERROR << std::to_string(state->currentOffset.frameNr) << " and flowkey " << std::to_string(flowkey);
            LOG_ERROR << "Missing data at begin of streaml!";
            //LOG_ERROR << "missing bytes: " << std::to_string(missing_count);
            soff = state->currentOffset.soff;
        }

        soff.length = missing_count;
        soff.start = 0;
        tcpPointer->offsets.push_back(soff);
        tcpPointer->flags.set(pcapfs::flags::MISSING_DATA);
    }

    if (state->gotCallback) {
        LOG_TRACE << "Multiple Callback in " << flowkey;
        // Search for packet in stored out of order packets
        TCPContent tcpcontent{tcpData.getData() + missing_str_len, tcpData.getDataLength() - missing_str_len};
        if (state->outOfOrderPackets.count(tcpcontent) == 1) {
            TCPOffset _offset = state->outOfOrderPackets.at(tcpcontent).front();
            state->outOfOrderPackets.at(tcpcontent).pop();
            tcpPointer->offsets.push_back(_offset.soff);
            LOG_TRACE << "Found matching out of order packet";
            LOG_TRACE << "Size of out of order buffer: " << state->outOfOrderPackets.size();
        } else {
            LOG_WARNING << "Out of order packet not found!";
        }
    } else {
        tcpPointer->offsets.push_back(state->currentOffset.soff);
    }

    state->gotCallback = true;
}

std::vector<pcapfs::FilePtr>
pcapfs::TcpFile::createVirtualFilesFromPcaps(const std::vector<pcapfs::FilePtr> &pcapFiles) {

    TCPIndexerState state;
    pcpp::TcpReassembly reassembly(&messageReadycallback, &state);
    PcapPtr pcapPtr;

    int icmpPackets = 0;


    for (auto &pcap: pcapFiles) {
        pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapFile>(pcap);

        state.currentPcapFileId = pcap->getIdInIndex();
        std::shared_ptr<pcpp::IFileReaderDevice> reader = pcapPtr->getReader();
        pcpp::RawPacket rawPacket;

        size_t pcapPosition = pcapPtr->getGlobalHeaderLen();

        for (size_t i = 1; reader->getNextPacket(rawPacket); i++) {

            pcpp::Packet parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP);
            state.currentTimestamp = utils::convertTimeValToTimePoint(rawPacket.getPacketTimeStamp());
            state.currentOffset.frameNr = i;

            pcapPosition += pcapPtr->getPacketHeaderLen();

            if (parsedPacket.isPacketOfType(pcpp::TCP) && parsedPacket.isPacketOfType(pcpp::IP)) {
                if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
                    icmpPackets++;
                }
                LOG_TRACE << "Found TCP packet, packet number: " << i;
                state.gotCallback = false;
                state.currentOffset.soff.id = state.currentPcapFileId;
                state.currentOffset.soff.start = pcapPosition;

                pcpp::Layer *l = parsedPacket.getFirstLayer();//->getDataLen();
                state.currentOffset.soff.start += l->getHeaderLen();
                while (l->getProtocol() != pcpp::TCP) {
                    l = l->getNextLayer();
                    state.currentOffset.soff.start += l->getHeaderLen();
                }
                pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                state.currentOffset.soff.length = calcIpPayload(parsedPacket) - tcpLayer->getHeaderLen();

                reassembly.reassemblePacket(parsedPacket);

                if (!state.gotCallback) {
                    if (tcpLayer->getLayerPayloadSize() > 0) {
                        if (state.currentOffset.soff.length > 0) {
                            TCPContent t(tcpLayer->getLayerPayload(), state.currentOffset.soff.length);
                            state.outOfOrderPackets[t].push(state.currentOffset);
                            LOG_TRACE << "Out of order packet found, buffer size: "
                                      << state.outOfOrderPackets.size();
                        }
                    }
                }
            }
            pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
        }
        pcapPtr->closeReader();
    }
    state.gotCallback = true;
    reassembly.closeAllConnections();

    if (icmpPackets > 0) {
        LOG_TRACE << "DEBUG: TCP inside of ICMP found -> " << icmpPackets << " packets skipped";
    }
    LOG_TRACE << "Final out of order packet buffer size: " << state.outOfOrderPackets.size();

    std::vector<pcapfs::FilePtr> result;
    for (auto &f : state.files) {
        //f.second->connectionBreaks.push_back(f.second->getFilesizeRaw());
        result.push_back(std::static_pointer_cast<pcapfs::File>(f.second));
    }
    return result;
}

size_t pcapfs::TcpFile::TCPContentHasher::operator()(const pcapfs::TcpFile::TCPContent &t) const {
    size_t _hash = 0;
    for (size_t pos = 0; pos + sizeof(size_t) <= t.datalen; pos += sizeof(size_t)) {
        _hash ^= std::hash<size_t>()(*(size_t *) (t.data + pos));
    }
    return _hash;
}


bool pcapfs::TcpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("tcp", pcapfs::TcpFile::create);


pcapfs::TcpFile::TCPContent::~TCPContent() {
    delete[] data;
}

pcapfs::TcpFile::TCPContent::TCPContent(const TCPContent &other) {
    datalen = other.datalen;
    if (other.data != nullptr) {
        data = new uint8_t[datalen];
        memcpy(this->data, other.data, this->datalen);
    }
}

pcapfs::TcpFile::TCPContent::TCPContent(uint8_t *copy_from, size_t datalen) {
    this->datalen = datalen;
    if (copy_from != nullptr) {
        data = new uint8_t[datalen];
        memcpy(data, copy_from, datalen);
    } else {
        data = nullptr;
    }
}

bool pcapfs::TcpFile::TCPContent::isEqual(const uint8_t *Other, size_t other_len) const {
    if (this->datalen != other_len) {
        return false;
    }
    for (size_t i = 0; i < this->datalen; i++) {
        if (this->data[i] != Other[i]) {
            return false;
        }
    }
    return true;
}