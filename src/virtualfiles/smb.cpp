#include "smb.h"
#include "smb/smb_messages.h"
#include "../filefactory.h"
#include "../logging.h"

#include <numeric>


std::vector<pcapfs::FilePtr> pcapfs::SmbFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx;
    std::vector<pcapfs::FilePtr> resultVector;
    const Bytes data = filePtr->getBuffer();
    if (!isSmbTraffic(filePtr, data))
        return resultVector;

    LOG_TRACE << "detected SMB2 traffic and start parsing";
    std::shared_ptr<SmbFile> controlFilePtr = std::make_shared<SmbFile>();
    controlFilePtr->fillGlobalProperties(controlFilePtr, filePtr);
    controlFilePtr->setFilename("SMB2.control");
    controlFilePtr->flags.set(pcapfs::flags::IS_METADATA);
    uint16_t usedDialect = smb::SMB_VERSION_UNKNOWN;

    std::stringstream ss;
    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();
    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = filePtr->connectionBreaks.at(i).first;
        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        // we currently only support direct SMB over TCP. There, we have a 4 byte
        // direct TCP transport packet header indicating the size of the following SMB data
        size_t smbDataSize = be32toh(*(uint32_t*) &data.at(offset));
        size_t currPos = 0;
        while (smbDataSize != 0 && smbDataSize <= (size - currPos)) {

            // skip direct TCP transport packet header
            offset += 4;
            currPos += 4;

            size_t accumulatedSmbPacketSize = 0;
            while (accumulatedSmbPacketSize < smbDataSize) {
                smb::SmbPacket smbPacket;
                try {
                    smbPacket = smb::SmbPacket(data.data() + offset, smbDataSize - accumulatedSmbPacketSize, usedDialect);
                } catch (const SmbError &err) {
                    LOG_WARNING << "Failed to parse SMB2 packet: " << err.what();
                    offset += smbDataSize;
                    currPos += smbDataSize;
                    break;
                }

                Fragment fragment;
                fragment.id = filePtr->getIdInIndex();
                fragment.start = offset;

                if (smbPacket.headerType == smb::HeaderType::SMB2_PACKET_HEADER) {
                    const std::shared_ptr<smb::SmbPacketHeader> packetHeader = std::static_pointer_cast<smb::SmbPacketHeader>(smbPacket.header);
                    //ss << (smbPacket.isResponse ? "[<] " : "[>] ") << smbPacket.command << smbPacket.message.totalSize << std::endl;
                    ss << (smbPacket.isResponse ? "[<] " : "[>] ") << smbPacket.command << std::endl;

                    if (smbPacket.isResponse && packetHeader->command == smb::Command::SMB2_NEGOTIATE)
                        usedDialect = smbPacket.dialect;

                    if (packetHeader->chainOffset != 0) {
                        // we have chained SMB2 data directly next
                        // without direct TCP transport packet header in between
                        fragment.length = smbPacket.size;
                        controlFilePtr->fragments.push_back(fragment);
                        offset += packetHeader->chainOffset;
                        currPos += packetHeader->chainOffset;
                        accumulatedSmbPacketSize += packetHeader->chainOffset;

                    } else if (packetHeader->flags & smb::PacketHeaderFlags::SMB2_FLAGS_RELATED_OPERATIONS) {
                        // last chunk of a sequence of chained SMB2 data
                        fragment.length = smbPacket.size;
                        controlFilePtr->fragments.push_back(fragment);
                        offset += smbPacket.size;
                        currPos += smbPacket.size;
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
                    ss << "[<|>] " << smbPacket.command << std::endl;

                    fragment.length = smbDataSize;
                    controlFilePtr->fragments.push_back(fragment);
                    offset += smbDataSize;
                    currPos += smbDataSize;
                    break;

                } else if (smbPacket.headerType == smb::HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED) {
                    ss << "[<|>] " << smbPacket.command << std::endl;

                    fragment.length = smbPacket.size;
                    controlFilePtr->fragments.push_back(fragment);
                    offset += smbPacket.size;
                    currPos += smbPacket.size;
                    accumulatedSmbPacketSize += smbPacket.size;
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
    controlFilePtr->flags.set(pcapfs::flags::PROCESSED);
    controlFilePtr->setFilesizeRaw(filesize);
    controlFilePtr->setFilesizeProcessed(ss.str().size());
    controlFilePtr->setSmbVersion(usedDialect);

    resultVector.push_back(controlFilePtr);
    return resultVector;
}


bool pcapfs::SmbFile::isSmbTraffic(const FilePtr &filePtr, const Bytes &data) {
    const uint8_t SMB_MAGIC[4] = {0xFE, 0x53, 0x4D, 0x42};
    if (filePtr->getProperty("protocol") == "tcp" &&
        (filePtr->getProperty("srcPort") == "445" || filePtr->getProperty("dstPort") == "445") &&
        data.size() > 68 && data.at(0) == 0x00 && memcmp(&data.at(4), SMB_MAGIC, 4) == 0)
        // currently only support direct SMB2 over TCP
        return true;
    else
        return false;
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
}


/**size_t pcapfs::SmbFile::calculateProcessedSize(const Index &idx) {
    std::vector<Bytes> totalContent;
    for (const Fragment fragment: fragments) {
        Bytes rawData(fragment.length);
        const FilePtr filePtr = idx.get({offsetType, fragment.id});
        filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
        totalContent.push_back(rawData);
    }
    return parseSmbTraffic(totalContent).size();
}**/


std::string const pcapfs::SmbFile::parseSmbTraffic(const std::vector<Bytes> &smbData) {
    std::stringstream ss;
    for (const Bytes &chunk : smbData) {
        smb::SmbPacket smbPacket(chunk.data(), chunk.size(), smbVersion);
        if (smbPacket.headerType == smb::SMB2_TRANSFORM_HEADER)
            ss << "[<|>]" << smbPacket.command << std::endl;
        else
            ss << (smbPacket.isResponse ? "[<] " : "[>] ") << smbPacket.command << std::endl;
            //ss << (smbPacket.isResponse ? "[<] " : "[>] ") << smbPacket.command <<  smbPacket.message.totalSize << std::endl;
    }
    return ss.str();
}


size_t pcapfs::SmbFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    std::vector<Bytes> totalContent;
    for (const Fragment fragment: fragments) {
        Bytes rawData(fragment.length);
        const FilePtr filePtr = idx.get({offsetType, fragment.id});
        filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
        totalContent.push_back(rawData);
    }
    const std::string outputString = parseSmbTraffic(totalContent);
    memcpy(buf, outputString.c_str() + startOffset, length);
    return std::min((size_t) outputString.length() - startOffset, length);
}


void pcapfs::SmbFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << smbVersion;
}


void pcapfs::SmbFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    archive >> smbVersion;
}


bool pcapfs::SmbFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbcontrol", pcapfs::SmbFile::create, pcapfs::SmbFile::parse);
