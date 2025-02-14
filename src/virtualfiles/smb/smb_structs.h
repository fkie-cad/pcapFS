#ifndef PCAPFS_SMB_STRUCTS_H
#define PCAPFS_SMB_STRUCTS_H

#include "smb_constants.h"
#include "smb_utils.h"
#include "../serverfile_manager.h"
#include "../../file.h"
#include "../../exceptions.h"
#include <memory>
#include <cstring>
#include <pcapplusplus/IpAddress.h>
#include <boost/serialization/map.hpp>
#include <boost/serialization/unordered_map.hpp>


namespace pcapfs {
    namespace smb {

        struct SmbTimestamps {
            SmbTimestamps() = default;
            SmbTimestamps(const std::map<TimePoint, ServerFileTimestamps>& inFsTimestamps,
                            const std::map<TimePoint, ServerFileTimestamps>& inHybridTimestamps) :
                            fsTimestamps(inFsTimestamps), hybridTimestamps(inHybridTimestamps) {}

            std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps> const getAllTimestamps() {
                // returns union of hybridTimestamps and fsTimestamps
                std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps> result = hybridTimestamps;
                for (const auto &entry: fsTimestamps) {
                    if (!result.count(entry.first))
                        result[entry.first] = entry.second;
                }
                return result;
            }

            template<class Archive>
            void serialize(Archive &archive, const unsigned int) {
                archive & fsTimestamps;
                archive & hybridTimestamps;
            }

            std::map<TimePoint, ServerFileTimestamps> fsTimestamps;
            std::map<TimePoint, ServerFileTimestamps> hybridTimestamps;
        };

        // map treeId - tree name
        typedef std::unordered_map<uint32_t, std::string> SmbTreeNames;

        // Identifier for an SMB server, used as part of ServerEndpointTree
        struct ServerEndpoint {
            ServerEndpoint() = default;
            explicit ServerEndpoint(const FilePtr &filePtr) {
                const uint16_t srcPort = strToUint16(filePtr->getProperty(prop::srcPort));
                if (srcPort == 445 || srcPort == 139) {
                    ipAddress = pcpp::IPAddress(filePtr->getProperty(prop::srcIP));
                    port = srcPort;
                } else {
                    // take dstIP and dstPort as server endpoint
                    // this might be client IP and client port if checkNonDefaultPorts config is set
                    // and the server does not use the default port 445 or 139
                    ipAddress = pcpp::IPAddress(filePtr->getProperty(prop::dstIP));
                    port = strToUint16(filePtr->getProperty(prop::dstPort));
                }
            }
            pcpp::IPAddress ipAddress;
            uint16_t port = 0;
            uint64_t sessionId = 0;

            bool operator==(const ServerEndpoint &endp) const {
                return endp.ipAddress == ipAddress && endp.port == port;
            };

            bool operator<(const ServerEndpoint &endp) const {
                if (ipAddress == endp.ipAddress)
                    if (port == endp.port)
                        return sessionId < endp.sessionId;
                    else
                        return port < endp.port;
                else
                    return ipAddress < endp.ipAddress;
            };

            template<class Archive>
            void serialize(Archive &archive, const unsigned int) {
                archive & ipAddress;
                archive & port;
                archive & sessionId;
            }

        };

        // Identifier for an SMB server tree, used as key for managing the extracted file information in SmbManager
        struct ServerEndpointTree : ServerFileTree {
            ServerEndpointTree() = default;
            ServerEndpointTree(const ServerEndpoint &endp, const std::string &inTreeName) : serverEndpoint(endp), treeName(inTreeName) {}
            ServerEndpoint serverEndpoint;
            std::string treeName = "";

            bool operator==(const ServerEndpointTree &endpt) const {
                return endpt.serverEndpoint == serverEndpoint && endpt.treeName == treeName;
            };

            bool operator<(const ServerEndpointTree &endpt) const {
                if (serverEndpoint == endpt.serverEndpoint)
                    return treeName < endpt.treeName;
                else
                    return serverEndpoint < endpt.serverEndpoint;
            };

            template<class Archive>
            void serialize(Archive &archive, const unsigned int) {
                archive & serverEndpoint;
                archive & treeName;
            }
        };

        struct CloseRequestData {
            std::string fileId = "";
            bool postqueryAttrib = false;
        };

        // for memorizing requested file information between query info request and response
        struct QueryInfoRequestData {
            uint8_t infoType = 0;
            uint8_t fileInfoClass = 0;
            std::string fileId = "";
        };

        // for memorizing requested file information between query directory request and response
        struct QueryDirectoryRequestData {
            uint8_t fileInfoClass = 0;
            std::string fileId = "";
        };

        struct ReadRequestData {
            std::string fileId = "";
            uint64_t readOffset = 0;
        };

        struct WriteRequestData {
            std::string fileId = "";
            uint64_t writeOffset = 0;
            uint32_t writeLength = 0;
            uint16_t dataOffset = 0;
            // globalOffset is the offset into the TCP file, where the write payload is located
            uint64_t globalOffset = 0;
        };


        struct FileMetaData{
            bool isDirectory = false;
            uint64_t creationTime = 0;
            uint64_t lastAccessTime = 0;
            uint64_t lastWriteTime = 0;
            uint64_t changeTime = 0;
        };
        typedef std::shared_ptr<FileMetaData> FileMetaDataPtr;

        struct SetInfoRequestData {
            std::string fileId = "";
            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
        };

        // holds information to be memorized along one SMB TCP connection
        struct SmbContext : ServerFileContext {
            SmbContext(const FilePtr &filePtr, bool inCreateServerFiles) :
                    ServerFileContext(filePtr), serverEndpoint(filePtr), createServerFiles(inCreateServerFiles),
                    clientIP(determineClientIP(filePtr)) {}

            ServerEndpoint serverEndpoint;
            uint16_t dialect = 0;

            // map messageId - filename
            std::map<uint64_t, std::string> createRequestFileNames;

            // map messageId - CloseRequestData
            std::map<uint64_t, std::shared_ptr<CloseRequestData>> closeRequestData;

            // map messageId - QueryInfoRequestData
            std::map<uint64_t, std::shared_ptr<QueryInfoRequestData>> queryInfoRequestData;

            // map messageId - QueryDirectoryRequestData
            std::map<uint64_t, std::shared_ptr<QueryDirectoryRequestData>> queryDirectoryRequestData;

            // map messageId - ReadRequestData
            std::map<uint64_t, std::shared_ptr<ReadRequestData>> readRequestData;

            // map messageId - WriteRequestData
            std::map<uint64_t, std::shared_ptr<WriteRequestData>> writeRequestData;

            // map messageId - SetInfoRequestData
            std::map<uint64_t, std::shared_ptr<SetInfoRequestData>> setInfoRequestData;

            // map messageId - tree name
            std::map<uint64_t, std::string> requestedTrees;

            uint32_t currentTreeId = 0;

            // current offset into the underlying TCP file, needed for handling reads
            uint64_t currentOffset = 0;

            // time skew between SMB share time and network time
            std::chrono::seconds timeSkew = std::chrono::seconds(0);

            bool createServerFiles = false;

            std::string clientIP;

            TimePoint currentTimestamp;
        };
        typedef std::shared_ptr<SmbContext> SmbContextPtr;


        // for extracting relevant file information out of query directory responses
        struct FileInformation {
            explicit FileInformation(const Bytes &rawContent, uint8_t fileInfoClass) {
                if (rawContent.size() < 64)
                    throw SmbError("Invalid size of file information struct");
                metaData->creationTime = *(uint64_t*) &rawContent.at(8);
                metaData->lastAccessTime = *(uint64_t*) &rawContent.at(16);
                metaData->lastWriteTime = *(uint64_t*) &rawContent.at(24);
                metaData->changeTime = *(uint64_t*) &rawContent.at(32);
                const uint32_t extractedFileAttributes = *(uint32_t*) &rawContent.at(56);
                metaData->isDirectory = extractedFileAttributes & 0x10;
                const uint32_t extractedFileNameLength = *(uint32_t*) &rawContent.at(60);
                switch (fileInfoClass) {
                    case FileInfoClass::FILE_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 64 > rawContent.size())
                            throw SmbError("Invalid file name length in FileDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(64), &rawContent.at(64 + extractedFileNameLength - 1)));
                        break;
                    case FileInfoClass::FILE_FULL_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 68 > rawContent.size())
                            throw SmbError("Invalid file name length in FileFullDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(68), &rawContent.at(68 + extractedFileNameLength - 1)));
                        break;
                    case FileInfoClass::FILE_ID_FULL_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 80 > rawContent.size())
                            throw SmbError("Invalid file name length in FileIdFullDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(80), &rawContent.at(80 + extractedFileNameLength - 1)));
                        break;
                    case FileInfoClass::FILE_BOTH_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 94 > rawContent.size())
                            throw SmbError("Invalid file name length in FileBothDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(94), &rawContent.at(94 + extractedFileNameLength - 1)));
                        break;
                    case FileInfoClass::FILE_ID_BOTH_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 104 > rawContent.size())
                            throw SmbError("Invalid file name length in FileIdBothDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(104), &rawContent.at(104 + extractedFileNameLength - 1)));
                        break;
                    case FileInfoClass::FILE_ID_EXTD_DIRECTORY_INFORMATION:
                        if (extractedFileNameLength + 88 > rawContent.size())
                            throw SmbError("Invalid file name length in FileIdExtdDirectoryInformation");
                        filename = wstrToStr(Bytes(&rawContent.at(88), &rawContent.at(88 + extractedFileNameLength - 1)));
                        break;
                }
                filename = sanitizeFilename(filename);
            };

            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
            std::string filename = "";
        };


        struct SmbHeader {};

        struct Smb1Header : SmbHeader {
            explicit Smb1Header(const uint8_t* rawData) {
                memcpy(&protocol, rawData, 4);
                memcpy(&command, rawData+4, 1);
                memcpy(&status, rawData+5, 4);
                memcpy(&flags, rawData+9, 1);
                memcpy(&flags2, rawData+10, 2);
                memcpy(&pidHigh, rawData+12, 2);
                memcpy(&securityFeatures, rawData+14, 8);
                memcpy(&tid, rawData+24, 2);
                memcpy(&pidLow, rawData+26, 2);
                memcpy(&uid, rawData+28, 2);
                memcpy(&mid, rawData+30, 2);
            };

            uint32_t protocol;
            uint8_t command;
            uint32_t status;
            uint8_t flags;
            uint16_t flags2;
            uint16_t pidHigh;
            uint8_t securityFeatures[8];
            uint16_t tid;
            uint16_t pidLow;
            uint16_t uid;
            uint16_t mid;
        };


        struct Smb2Header : SmbHeader {
            explicit Smb2Header(const uint8_t* rawData) {
                memcpy(&protocolId, rawData, 4);
                memcpy(&headerLength, rawData+4, 2);
                memcpy(&creditCharge, rawData+6, 2);
                memcpy(&status, rawData+8, 4);
                memcpy(&command, rawData+12, 2);
                memcpy(&requestedCredits, rawData+14, 2);
                memcpy(&flags, rawData+16, 4);
                memcpy(&chainOffset, rawData+20, 4);
                memcpy(&messageId, rawData+24, 8);
                memcpy(&processId, rawData+32, 4);
                memcpy(&treeId, rawData+36, 4);
                memcpy(&sessionId, rawData+40, 8);
                memcpy(&signature, rawData+48, 16);
            };

            uint32_t protocolId; // "\xFE SMB" magic bytes
            uint16_t headerLength; // always 64
            uint16_t creditCharge;
            uint32_t status; // also ChannelSequence/Reserved depending on dialect
            uint16_t command;
            uint16_t requestedCredits;
            uint32_t flags; // indicating Request/Response or SYNC/ASYNC
            uint32_t chainOffset;
            uint64_t messageId;
            uint32_t processId; // 8 byte asyncId when ASYNC
            uint32_t treeId;
            uint64_t sessionId;
            uint8_t signature[16];
        };


        struct SmbTransformHeader : SmbHeader {
            explicit SmbTransformHeader(const uint8_t* rawData) {
                memcpy(&protocolId, rawData, 4);
                memcpy(&signature, rawData+4, 16);
                memcpy(&nonce, rawData+20, 16);
                memcpy(&messageSize, rawData+36, 4);
                memcpy(&flags, rawData+42, 2);
                memcpy(&sessionId, rawData+44, 8);
            };

            uint32_t protocolId; // "\xFD SMB" magic bytes
            uint8_t signature[16];
            uint8_t nonce[16];
            uint32_t messageSize;
            uint16_t flags; // encryption algorithm for SMB 3.0/3.0.2
            uint64_t sessionId;
        };


        struct SmbCompressionTransformHeader : SmbHeader {
            explicit SmbCompressionTransformHeader(const uint8_t* rawData) {
                memcpy(&protocolId, rawData, 4);
                memcpy(&uncompressedDataSize, rawData+4, 4);
                memcpy(&compressionAlgorithm, rawData+8, 2);
                memcpy(&flags, rawData+10, 2);
            };

            uint32_t protocolId;
            uint32_t uncompressedDataSize;
            uint16_t compressionAlgorithm;
            uint16_t flags;
        };


        struct SmbCompressionTransformHeaderUnchained : SmbCompressionTransformHeader {
            explicit SmbCompressionTransformHeaderUnchained(const uint8_t* rawData) : SmbCompressionTransformHeader(rawData) {
                memcpy(&offset, rawData+12, 4);
            };

            uint32_t offset;
        };


        struct SmbCompressionTransformHeaderChained : SmbCompressionTransformHeader {
            explicit SmbCompressionTransformHeaderChained(const uint8_t* rawData) : SmbCompressionTransformHeader(rawData) {
                memcpy(&length, rawData+12, 4);
                if (usesOriginalPayloadSizeField())
                    memcpy(&originalPayloadSize, rawData+16, 4);
            };

            bool usesOriginalPayloadSizeField() const {
                return (compressionAlgorithm == CompressionAlgorithms::LZNT1 ||
                    compressionAlgorithm == CompressionAlgorithms::LZ77 ||
                    compressionAlgorithm == CompressionAlgorithms::LZ77_HUFFMAN);
            };

            uint32_t length;
            uint32_t originalPayloadSize = 0;
        };
    }
}

#endif //PCAPFS_SMB_STRUCTS_H
