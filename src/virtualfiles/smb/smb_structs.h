#ifndef PCAPFS_SMB_STRUCTS_H
#define PCAPFS_SMB_STRUCTS_H

#include "smb_constants.h"
#include "smb_utils.h"
#include "../../file.h"
#include "../../exceptions.h"
#include <memory>
#include <cstring>
#include <pcapplusplus/IpAddress.h>

namespace pcapfs {
    namespace smb {

        // Identifier for an SMB server tree, used as key for managing the extracted file information in the SMBManager
        struct ServerEndpoint {
            pcpp::IPAddress ipAddress;
            uint16_t port = 0;
            uint32_t treeId = 0;

            bool operator==(const ServerEndpoint &endp) const {
                return endp.ipAddress == ipAddress && endp.port == port && endp.treeId == treeId;
            };

            bool operator<(const ServerEndpoint &endp) const {
                if (ipAddress == endp.ipAddress) {
                    if (port == endp.port)
                        return treeId < endp.treeId;
                    else
                        return port < endp.port;
                } else
                    return ipAddress < endp.ipAddress ;
            };
        };

        // for memorizing requested file information between query info request and response
        struct QueryInfoRequestData {
            uint8_t infoType = 0;
            uint8_t fileInfoClass = 0;
            std::string fileId = "";
        };

        // for memorizing requested file information between query info request and response
        struct QueryDirectoryRequestData {
            uint8_t fileInfoClass = 0;
            std::string fileId = "";
        };

        // holds information to be memorized along one SMB TCP connection
        struct SmbContext {
            explicit SmbContext(const FilePtr &filePtr) : offsetFile(filePtr) {}
            uint16_t dialect = 0;
            // map guid - filename
            std::unordered_map<std::string, std::string> fileHandles;
            std::string currentCreateRequestFile = "";
            std::shared_ptr<QueryInfoRequestData> currentQueryInfoRequestData = nullptr;
            std::shared_ptr<QueryDirectoryRequestData> currentQueryDirectoryRequestData = nullptr;
            FilePtr offsetFile = nullptr;
            // map treeId - tree name
            std::map<uint32_t, std::string> treeNames;
            std::string currentRequestedTree = "";
        };

        typedef std::shared_ptr<SmbContext> SmbContextPtr;

        // for extracting relevant file information out of query directory responses
        struct FileInformation {
            explicit FileInformation(const Bytes &rawContent, uint8_t fileInfoClass) {
                if (rawContent.size() < 64)
                    throw SmbError("Invalid size of file information struct");
                lastAccessTime = *(uint64_t*) &rawContent.at(16);
                filesize = *(uint64_t*) &rawContent.at(40);
                const uint32_t extractedFileAttributes = *(uint32_t*) &rawContent.at(56);
                isDirectory = extractedFileAttributes & 0x10;
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
            };

            bool isDirectory = false;
            uint64_t lastAccessTime = 0;
            uint64_t filesize = 0;
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