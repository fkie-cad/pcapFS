#include "tcp.h"

#include <netinet/in.h>
#include <memory>
#include <string>
#include <vector>
#include <fstream>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/PacketUtils.h>

#include "../dirlayout.h"
#include "../utils.h"
#include "../capturefiles/pcap.h"
#include "../capturefiles/pcapng.h"


size_t pcapfs::TcpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    size_t fragmentsPos = 0;
    size_t posInFragment = 0;
    size_t position = 0;

    // seek to start_offset
    while (position < startOffset) {
        position += fragments[fragmentsPos].length;
        fragmentsPos++;
    }

    if (position > startOffset) {
        fragmentsPos--;
        if (fragmentsPos >= fragments.size())
            return 0;
        posInFragment = fragments.at(fragmentsPos).length - (position - startOffset);
        position = static_cast<size_t>(startOffset);
    }

    while (position < startOffset + length && fragmentsPos < fragments.size()) {
        const size_t toRead = std::min(fragments.at(fragmentsPos).length - posInFragment, length - (position - startOffset));
        //TODO: is start=0 really good for missing data?
        if (fragments.at(fragmentsPos).start == 0 && flags.test(pcapfs::flags::MISSING_DATA)) {
            // TCP missing data
            memset(buf + (position - startOffset), 0, toRead);
        } else {
            //TODO: offsets at which number?
            pcapfs::FilePtr filePtr = idx.get({this->offsetType, this->fragments.at(fragmentsPos).id});
            filePtr->read(fragments.at(fragmentsPos).start + posInFragment, toRead, idx, buf + (position - startOffset));
        }

        // set run variables in case next fragment is needed
        position += toRead;
        fragmentsPos++;
        posInFragment = 0;
    }

    if (startOffset + length < filesizeRaw) {
        return length;
    } else {
        return filesizeRaw - startOffset;
    }
}


void pcapfs::TcpFile::messageReadycallback(signed char side, const pcpp::TcpStreamData &tcpData, void *userCookie) {
    TCPIndexerState *state = static_cast<pcapfs::TcpFile::TCPIndexerState *>(userCookie);

    const uint64_t flowkey = (static_cast<uint64_t>(state->currentGeneration) << 32) | tcpData.getConnectionData().flowKey;
    pcapfs::TcpFile::TCPPtr tcpPointer;

    if (tcpData.getDataLength() == 0) {
        LOG_TRACE << "Empty tcp Data";
    }

    size_t tcpDataLength = 0;
    if (state->currentFragment.fragment.length > tcpData.getDataLength()) {
        LOG_TRACE << "Partial retransmission found";
        const size_t overlapSize = state->currentFragment.fragment.length - tcpData.getDataLength();
        state->currentFragment.fragment.start += overlapSize;
        state->currentFragment.fragment.length -= overlapSize;
        tcpDataLength = state->currentFragment.fragment.length;
    } else {
        tcpDataLength = tcpData.getDataLength();
    }

    if (state->files.find(flowkey) == state->files.end()) {
        LOG_TRACE << "New file with key: " << flowkey;

        state->files.emplace(flowkey, std::make_shared<pcapfs::TcpFile>());
        state->currentSide.insert(std::pair<uint64_t, signed char>(flowkey, side));
        tcpPointer = state->files[flowkey];

        tcpPointer->setFirstPacketNumber(state->currentFragment.frameNr);
        tcpPointer->setTimestamp(state->currentTimestamp);
        tcpPointer->setFilename("tcp" + std::to_string(state->nextUniqueId));
        tcpPointer->setIdInIndex(state->nextUniqueId);
        tcpPointer->setOffsetType(state->isPcapng ? "pcapng" : "pcap"); //tcp files point directly into the pcap
        tcpPointer->setFilesizeRaw(tcpDataLength);
        tcpPointer->setFilesizeProcessed(tcpDataLength);
        tcpPointer->setFiletype("tcp");
        tcpPointer->connectionBreaks.emplace_back(0, state->currentTimestamp);

        tcpPointer->setProperty(prop::srcIP, tcpData.getConnectionData().srcIP.toString());
        tcpPointer->setProperty(prop::dstIP, tcpData.getConnectionData().dstIP.toString());
        tcpPointer->setProperty(prop::srcPort, std::to_string(tcpData.getConnectionData().srcPort));
        tcpPointer->setProperty(prop::dstPort, std::to_string(tcpData.getConnectionData().dstPort));
        tcpPointer->setProperty(prop::protocol, "tcp");
        ++state->nextUniqueId;
    } else {
        tcpPointer = state->files[flowkey];
        tcpPointer->setFilesizeRaw(tcpPointer->getFilesizeRaw() + tcpDataLength);
        tcpPointer->setFilesizeProcessed(tcpPointer->getFilesizeRaw());
    }

    if (state->currentSide[flowkey] != side) {
        //current filesize (without tcp data) equals the offset in tcp stream where break occurred
        state->currentSide[flowkey] = side;
        tcpPointer->connectionBreaks.emplace_back(tcpPointer->getFilesizeRaw() - tcpDataLength,
                                                  state->currentTimestamp);

    }

    std::string datastr = std::string((char *) tcpData.getData(), tcpData.getDataLength());
    unsigned long missing_count = 0;
    unsigned long missing_str_len = 0;
    if (datastr.find("bytes missing]") != std::string::npos) {
        missing_str_len = datastr.find(']') + 1;
        sscanf(datastr.c_str(), "[ %lu bytes missing]", &missing_count);
        LOG_TRACE << missing_count << " bytes of missing TCP-data found";
        /* Which side is the missing data?? -> The last side seen
         * What if missing data at start of stream? -> No information, assuming(!!) first side seen after
         * Is the missing data spread over several HTTP-messages or even sides?! -> Assuming no
         */
        Fragment fragment;

        if (!tcpPointer->fragments.empty()) {
            fragment = tcpPointer->fragments.back();
        } else {
            LOG_ERROR << "Missing data at begin of stream!";
            fragment = state->currentFragment.fragment;
        }

        fragment.length = missing_count;
        fragment.start = 0;
        tcpPointer->fragments.push_back(fragment);
        tcpPointer->flags.set(pcapfs::flags::MISSING_DATA);

        tcpPointer->setFilesizeRaw(tcpPointer->getFilesizeRaw() + missing_count - missing_str_len);
        tcpPointer->setFilesizeProcessed(tcpPointer->getFilesizeRaw());
    }

    if (state->gotCallback) {
        LOG_TRACE << "Multiple Callback in " << flowkey;
        // Search for packet in stored out of order packets
        TCPContent tcpcontent{tcpData.getData() + missing_str_len, tcpData.getDataLength() - missing_str_len};
        if (state->outOfOrderPackets.count(tcpcontent) == 1) {
            TCPFragment _fragment = state->outOfOrderPackets.at(tcpcontent).front();
            state->outOfOrderPackets.at(tcpcontent).pop();
            tcpPointer->fragments.push_back(_fragment.fragment);
            LOG_TRACE << "Found matching out of order packet";
            LOG_TRACE << "Size of out of order buffer: " << state->outOfOrderPackets.size();
        } else {
            LOG_WARNING << "Out of order packet not found!";
        }
    } else {
        tcpPointer->fragments.push_back(state->currentFragment.fragment);
    }

    state->gotCallback = true;
}

std::vector<pcapfs::FilePtr>
pcapfs::TcpFile::createVirtualFilesFromPcaps(const std::vector<pcapfs::FilePtr> &pcapFiles) {

    TCPIndexerState state;
    // One reassembly instance per connection generation: the library ignores every packet of a flow it has seen
    // closing, so a new connection on the same 5-tuple is handed to the next instance (see FlowGeneration).
    std::vector<std::unique_ptr<pcpp::TcpReassembly>> reassemblies;
    reassemblies.push_back(std::make_unique<pcpp::TcpReassembly>(&messageReadycallback, &state));

    std::shared_ptr<CaptureFile> pcapPtr;

    int icmpPackets = 0;

    for (auto &pcap: pcapFiles) {
        if (pcap->getFiletype() == "pcap"){
            pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapFile>(pcap);
            state.isPcapng = false;
        } else {
            pcapPtr = std::dynamic_pointer_cast<pcapfs::PcapNgFile>(pcap);
            state.isPcapng = true;
        }
        state.currentPcapFileId = pcap->getIdInIndex();
        std::shared_ptr<pcpp::IFileReaderDevice> reader = pcapPtr->getReader();
        pcpp::RawPacket rawPacket;

        size_t pcapPosition = pcapPtr->getOffsetFromLastBlock(0);

        for (size_t i = 1; reader->getNextPacket(rawPacket); i++) {

            pcpp::Packet parsedPacket = pcpp::Packet(&rawPacket, pcpp::TCP);
            state.currentTimestamp = utils::convertTimeValToTimePoint(rawPacket.getPacketTimeStamp());
            state.currentFragment.frameNr = i;

            pcapPosition += pcapPtr->getOffsetFromLastBlock(i);

            if (parsedPacket.isPacketOfType(pcpp::TCP) && parsedPacket.isPacketOfType(pcpp::IP)) {
                if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
                    icmpPackets++;
                }
                LOG_TRACE << "Found TCP packet, packet number: " << i;
                state.gotCallback = false;
                state.currentFragment.fragment.id = state.currentPcapFileId;
                state.currentFragment.fragment.start = pcapPosition;

                pcpp::Layer *l = parsedPacket.getFirstLayer();//->getDataLen();
                state.currentFragment.fragment.start += l->getHeaderLen();
                while (l->getProtocol() != pcpp::TCP) {
                    l = l->getNextLayer();
                    state.currentFragment.fragment.start += l->getHeaderLen();
                }
                pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                state.currentFragment.fragment.length = tcpLayer->getLayerPayloadSize();

                if (!parsedPacket.isPacketOfType(pcpp::ICMP)) {
                    FlowGeneration &flow = state.flowGenerations[pcpp::hash5Tuple(&parsedPacket)];
                    const pcpp::tcphdr *tcpHeader = tcpLayer->getTcpHeader();
                    if (tcpHeader->synFlag && !tcpHeader->ackFlag) {
                        const uint32_t synSeq = ntohl(tcpHeader->sequenceNumber);
                        // a SYN after the connection was closed, or a SYN with another initial sequence number
                        // after data/ACKs were exchanged, starts a new connection (a retransmitted SYN does not)
                        // (bounded, because every generation costs about 1 KB: beyond the limit a flow behaves as
                        // it did before generations existed, i.e. packets after the close are ignored)
                        if (flow.generation + 1 < MAX_CONNECTION_GENERATIONS &&
                            (flow.sawFinOrRst || (flow.sawNonSyn && !flow.knowsSynSeq(synSeq)))) {
                            const uint32_t next = flow.generation + 1;
                            flow = FlowGeneration();
                            flow.generation = next;
                        }
                        if (!flow.knowsSynSeq(synSeq) && flow.synSeqCount < 2)
                            flow.synSeqs[flow.synSeqCount++] = synSeq;
                        state.currentGeneration = flow.generation;
                    } else if ((tcpHeader->finFlag || tcpHeader->rstFlag) && flow.generation > 0 && !flow.sawSynAck &&
                               !flow.sawNonSyn &&
                               !(tcpHeader->ackFlag && flow.knowsSynSeq(ntohl(tcpHeader->ackNumber) - 1))) {
                        // a FIN/RST right after the SYN of a reconnect that does not answer that SYN is a late
                        // packet of the previous connection: it must not close the new one
                        // (only while nothing but SYNs was seen of the new connection: in a capture without the
                        // SYN-ACK, e.g. of one direction only, a later FIN/RST belongs to the new connection)
                        state.currentGeneration = flow.generation - 1;
                    } else {
                        flow.sawNonSyn = true;
                        if (tcpHeader->synFlag)
                            flow.sawSynAck = true;
                        if (tcpHeader->finFlag || tcpHeader->rstFlag)
                            flow.sawFinOrRst = true;
                        state.currentGeneration = flow.generation;
                    }
                    while (reassemblies.size() <= state.currentGeneration)
                        reassemblies.push_back(std::make_unique<pcpp::TcpReassembly>(&messageReadycallback, &state));
                } else {
                    state.currentGeneration = 0;
                }
                reassemblies[state.currentGeneration]->reassemblePacket(parsedPacket);

                if (!state.gotCallback) {
                    if (tcpLayer->getLayerPayloadSize() > 0) {
                        if (state.currentFragment.fragment.length > 0) {
                            TCPContent t(tcpLayer->getLayerPayload(), state.currentFragment.fragment.length);
                            state.outOfOrderPackets[t].push(state.currentFragment);
                            LOG_TRACE << "Out of order packet found, buffer size: "
                                      << state.outOfOrderPackets.size();
                        }
                    }
                }
            }
            if (!state.isPcapng)
                pcapPosition += parsedPacket.getFirstLayer()->getDataLen();
        }
        pcapPtr->closeReader();
    }
    state.gotCallback = true;
    for (size_t generation = 0; generation < reassemblies.size(); ++generation) {
        state.currentGeneration = static_cast<uint32_t>(generation);
        reassemblies[generation]->closeAllConnections();
    }

    if (icmpPackets > 0) {
        LOG_TRACE << "DEBUG: TCP inside of ICMP found -> " << icmpPackets << " packets skipped";
    }
    LOG_TRACE << "Final out of order packet buffer size: " << state.outOfOrderPackets.size();

    std::vector<pcapfs::FilePtr> result;
    std::transform(state.files.begin(), state.files.end(), std::back_inserter(result),
                    [](auto &f){ return std::static_pointer_cast<pcapfs::File>(f.second); });
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
        memcpy(data, other.data, datalen);
    } else {
        data = nullptr;
    }
}

pcapfs::TcpFile::TCPContent& pcapfs::TcpFile::TCPContent::operator=(const TCPContent &other) {
    if (this != &other) {
        delete[] data;
        datalen = other.datalen;
        if (other.data != nullptr) {
            data = new uint8_t[datalen];
            memcpy(data, other.data, datalen);
        } else {
            data = nullptr;
        }
    }
    return *this;
}

pcapfs::TcpFile::TCPContent::TCPContent(const uint8_t *copy_from, size_t datalen) {
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
