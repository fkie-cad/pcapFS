#ifndef PCAPFS_SMB_HEADERS_H
#define PCAPFS_SMB_HEADERS_H

#include "smb_constants.h"
#include <cstring>


namespace pcapfs {
    namespace smb {

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

#endif //PCAPFS_SMB_HEADERS_H
