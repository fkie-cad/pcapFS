#include "smbcontrol.h"
#include "smb/smb_packet.h"
#include "smb/smb_structs.h"
#include "smb/smb_constants.h"
#include "smb/smb_utils.h"
#include "../filefactory.h"
#include <numeric>


std::vector<pcapfs::FilePtr> pcapfs::SmbControlFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx;
    std::vector<pcapfs::FilePtr> resultVector;
    const Bytes data = filePtr->getBuffer();

    size_t offsetAfterNbssSetup = 0;
    bool hasNbssSessionSetup = false;
    if (!smb::isSmbOverTcp(filePtr, data, config.checkNonDefaultPorts)) {
        offsetAfterNbssSetup = smb::getSmbOffsetAfterNbssSetup(filePtr, data, config.checkNonDefaultPorts);
        if (offsetAfterNbssSetup == (size_t)-1)
            return resultVector;
        else
            hasNbssSessionSetup = true;
    }

    LOG_TRACE << "detected SMB traffic and start parsing";
    std::shared_ptr<SmbControlFile> controlFilePtr = std::make_shared<SmbControlFile>();
    controlFilePtr->fillGlobalProperties(controlFilePtr, filePtr);
    controlFilePtr->setFilename("SMB.control");
    controlFilePtr->flags.set(pcapfs::flags::IS_METADATA);

    bool reachedOffsetAfterNbssSetup = false;
    std::stringstream ss;
    smb::SmbContextPtr smbContext = std::make_shared<smb::SmbContext>(filePtr, true);
    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();
    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = filePtr->connectionBreaks.at(i).first;

        if (hasNbssSessionSetup && !reachedOffsetAfterNbssSetup) {
            if (offset == offsetAfterNbssSetup)
                reachedOffsetAfterNbssSetup = true;
            else
                continue;
        }

        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        // We have a 4 byte NBSS header indicating the NBSS message type
        // and the size of the following SMB data
        if (data.at(offset) != 0) {
            // message type has to be zero
            continue;
        }
        size_t smbDataSize = be32toh(*(uint32_t*) &data.at(offset));
        size_t currPos = 0;
        while (smbDataSize != 0 && smbDataSize <= (size - currPos)) {

            // skip NBSS header
            offset += 4;
            currPos += 4;

            size_t accumulatedSmbPacketSize = 0;
            while (accumulatedSmbPacketSize < smbDataSize) {
                smb::SmbPacket smbPacket;
                try {
                    smbContext->currentOffset = offset;
                    smbPacket = smb::SmbPacket(data.data() + offset, smbDataSize - accumulatedSmbPacketSize, smbContext);
                } catch (const SmbError &err) {
                    LOG_WARNING << "Failed to parse SMB2 packet: " << err.what();
                    offset += smbDataSize;
                    currPos += smbDataSize;
                    break;
                }

                ss << smbPacket.toString(smbContext);

                Fragment fragment;
                fragment.id = filePtr->getIdInIndex();
                fragment.start = offset;

                if (smbPacket.headerType == smb::HeaderType::SMB2_PACKET_HEADER) {
                    const std::shared_ptr<smb::Smb2Header> packetHeader = std::static_pointer_cast<smb::Smb2Header>(smbPacket.header);

                    if (packetHeader->chainOffset != 0) {
                        // we have chained SMB2 data directly next without NBSS header in between
                        LOG_TRACE << "SMB2 packet is chained";
                        fragment.length = smbPacket.size;
                        controlFilePtr->fragments.push_back(fragment);
                        offset += packetHeader->chainOffset;
                        currPos += packetHeader->chainOffset;
                        accumulatedSmbPacketSize += packetHeader->chainOffset;

                    } else if (packetHeader->flags & smb::Smb2HeaderFlags::SMB2_FLAGS_RELATED_OPERATIONS) {
                        LOG_TRACE << "SMB2 packet is last part of a chain";
                        // last chunk of a sequence of chained SMB2 data
                        const size_t packetLength = smbDataSize - accumulatedSmbPacketSize;
                        fragment.length = packetLength;
                        controlFilePtr->fragments.push_back(fragment);
                        offset += packetLength;
                        currPos += packetLength;
                        break;

                    } else {
                        // packet does not belong to chain in any way
                        fragment.length = smbDataSize;
                        controlFilePtr->fragments.push_back(fragment);
                        offset += smbDataSize;
                        currPos += smbDataSize;
                        break;
                    }

                } else if (smbPacket.headerType == smb::HeaderType::SMB2_TRANSFORM_HEADER ||
                            smbPacket.headerType == smb::HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED) {
                    fragment.length = smbDataSize;
                    controlFilePtr->fragments.push_back(fragment);
                    offset += smbDataSize;
                    currPos += smbDataSize;
                    break;

                } else if (smbPacket.headerType == smb::HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED) {
                    LOG_TRACE << "SMB2 packet chained with compression transform header";
                    fragment.length = smbPacket.size;
                    controlFilePtr->fragments.push_back(fragment);
                    offset += smbPacket.size;
                    currPos += smbPacket.size;
                    accumulatedSmbPacketSize += smbPacket.size;

                } else if (smbPacket.headerType == smb::HeaderType::SMB1_PACKET_HEADER) {
                    fragment.length = smbDataSize;
                    controlFilePtr->fragments.push_back(fragment);
                    offset += smbDataSize;
                    currPos += smbDataSize;
                    break;
                }
            }

            // fully parsed this connection break
            if (offset >= data.size())
                break;

            // get size of next SMB2 data
            smbDataSize = be32toh(*(uint32_t*) &data.at(offset));
        }
    }
    const size_t filesize = std::accumulate(controlFilePtr->fragments.begin(), controlFilePtr->fragments.end(), 0,
                                                            [](size_t counter, Fragment frag){ return counter + frag.length; });
    LOG_TRACE << "filesize of SMB control file: " << filesize;
    controlFilePtr->flags.set(pcapfs::flags::PROCESSED);
    controlFilePtr->setFilesizeRaw(filesize);
    const std::string processedContent = ss.str();
    controlFilePtr->setFilesizeProcessed(processedContent.size());

    // for faster access in read
    controlFilePtr->buffer.assign(processedContent.begin(), processedContent.end());

    resultVector.push_back(controlFilePtr);
    return resultVector;
}




void pcapfs::SmbControlFile::fillGlobalProperties(std::shared_ptr<SmbControlFile> &controlFilePtr, const FilePtr &filePtr) {
    controlFilePtr->setTimestamp(filePtr->connectionBreaks.at(0).second);
    controlFilePtr->setProperty("protocol", "smb");
    controlFilePtr->setFiletype("smbcontrol");
    controlFilePtr->setOffsetType(filePtr->getFiletype());
    controlFilePtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    controlFilePtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    controlFilePtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    controlFilePtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
}


size_t pcapfs::SmbControlFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

    bool buffer_needs_content = std::all_of(buffer.cbegin(), buffer.cend(),
                                            [](const auto &elem) { return elem == 0; });
    if(buffer_needs_content == false) {
        LOG_TRACE << "BUFFER HIT for read in SMB control file";
        if (buffer.size() >= startOffset + length) {
            memcpy(buf, (const char*) buffer.data() + startOffset, length);
            return length;
        } else {
            const size_t toRead = buffer.size() - startOffset;
            memcpy(buf, (const char*) buffer.data() + startOffset, toRead);
            return toRead;
        }
    } else {
        LOG_TRACE << "no buffer hit for read in SMB control file, starting read cascade";
        std::stringstream ss;
        const FilePtr filePtr = idx.get({offsetType, fragments.at(0).id});
        smb::SmbContextPtr smbContext = std::make_shared<smb::SmbContext>(filePtr, false);

        for (const Fragment fragment: fragments) {
            Bytes rawData(fragment.length);
            filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
            smb::SmbPacket smbPacket(rawData.data(), rawData.size(), smbContext);
            ss << smbPacket.toString(smbContext);
        }
        const std::string outputString = ss.str();
        memcpy(buf, outputString.c_str() + startOffset, length);
        buffer.assign(outputString.begin(), outputString.end());
        return std::min((size_t) outputString.length() - startOffset, length);
    }
}


bool pcapfs::SmbControlFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbcontrol", pcapfs::SmbControlFile::create, pcapfs::SmbControlFile::parse);
