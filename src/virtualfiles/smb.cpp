#include "smb.h"
#include "smb/smb_packet.h"
#include "smb/smb_structs.h"
#include "smb/smb_constants.h"
#include "../filefactory.h"
#include <numeric>


std::vector<pcapfs::FilePtr> pcapfs::SmbFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx;
    std::vector<pcapfs::FilePtr> resultVector;
    const Bytes data = filePtr->getBuffer();

    size_t offsetAfterNbssSetup = 0;
    bool hasNbssSessionSetup = false;
    if (!isSmbOverTcp(filePtr, data)) {
        offsetAfterNbssSetup = getSmbOffsetAfterNbssSetup(filePtr, data);
        if (offsetAfterNbssSetup == (size_t)-1)
            return resultVector;
        else
            hasNbssSessionSetup = true;
    }

    LOG_TRACE << "detected SMB traffic and start parsing";
    std::shared_ptr<SmbFile> controlFilePtr = std::make_shared<SmbFile>();
    controlFilePtr->fillGlobalProperties(controlFilePtr, filePtr);
    controlFilePtr->setFilename("SMB.control");
    controlFilePtr->flags.set(pcapfs::flags::IS_METADATA);

    bool reachedOffsetAfterNbssSetup = false;
    std::stringstream ss;
    smb::SmbContextPtr smbContext = std::make_shared<smb::SmbContext>(filePtr);
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


bool pcapfs::SmbFile::isSmbOverTcp(const FilePtr &filePtr, const Bytes &data) {
    if (filePtr->getProperty("protocol") == "tcp" &&
        data.size() > 68 && data.at(0) == 0x00 && be32toh(*(uint32_t*) &data.at(0)) != 0 &&
        (memcmp(&data.at(4), smb::SMB2_MAGIC, 4) == 0 || memcmp(&data.at(4), smb::SMB1_MAGIC, 4) == 0) &&
        (config.checkNonDefaultPorts || (filePtr->getProperty("srcPort") == "445" || filePtr->getProperty("dstPort") == "445")))
        return true;
    else
        return false;
}


size_t pcapfs::SmbFile::getSmbOffsetAfterNbssSetup(const FilePtr &filePtr, const Bytes &data) {
    // returns offset where smb Traffic begins after Netbios Session Setup
    if (filePtr->getProperty("protocol") == "tcp" && data.size() > 68 && (config.checkNonDefaultPorts ||
        (filePtr->getProperty("srcPort") == "139" || filePtr->getProperty("dstPort") == "139"))) {
        for (size_t pos = 0; pos < data.size() - 8; ++pos) {
            if (data.at(pos) == 0x00 && be32toh(*(uint32_t*) &data.at(pos)) != 0 &&
                (memcmp(&data.at(pos+4), smb::SMB2_MAGIC, 4) == 0 || memcmp(&data.at(pos+4), smb::SMB1_MAGIC, 4) == 0))
                return pos;
        }
    }
    return (size_t)-1;
}


void pcapfs::SmbFile::fillGlobalProperties(std::shared_ptr<SmbFile> &controlFilePtr, const FilePtr &filePtr) {
    controlFilePtr->setTimestamp(filePtr->connectionBreaks.at(0).second);
    controlFilePtr->setProperty("protocol", "smb");
    controlFilePtr->setFiletype("smbcontrol");
    controlFilePtr->setOffsetType(filePtr->getFiletype());
    controlFilePtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    controlFilePtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    controlFilePtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    controlFilePtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    controlFilePtr->setProperty("smbTree", "(controlfiles)");
}


size_t pcapfs::SmbFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {

    bool buffer_needs_content = std::all_of(buffer.cbegin(), buffer.cend(),
                                            [](const auto &elem) { return elem == 0; });
    if(buffer_needs_content == false) {
        LOG_TRACE << "BUFFER HIT for read in SMB control file";
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

    } else {
        LOG_TRACE << "no buffer hit for read in SMB control file, starting read cascade";
        std::stringstream ss;
        const FilePtr filePtr = idx.get({offsetType, fragments.at(0).id});
        smb::SmbContextPtr smbContext = std::make_shared<smb::SmbContext>(filePtr);

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


bool pcapfs::SmbFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbcontrol", pcapfs::SmbFile::create, pcapfs::SmbFile::parse);
