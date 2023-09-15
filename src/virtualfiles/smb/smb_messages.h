#ifndef PCAPFS_SMB_MESSAGES_H
#define PCAPFS_SMB_MESSAGES_H

#include "smb_headers.h"
#include "smb_utils.h"
#include "../../exceptions.h"
#include "../../commontypes.h"


namespace pcapfs {
    namespace smb {

        class SmbMessage {
        public:
            SmbMessage() : rawData(0) {}
            SmbMessage(const uint8_t* data, size_t len) : rawData(data, data+len), totalSize(len) {};
            Bytes rawData;
            size_t totalSize = 0;
        };

        class ErrorResponse : public SmbMessage {
        public:
            ErrorResponse(const uint8_t* data, size_t len) : SmbMessage(data, len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 9)
                    throw PcapFsException("Invalid StructureSize in SMB2 Error Response");

                const uint32_t byteCount = *(uint32_t*) &rawData.at(4);
                if (byteCount > len - 6)
                    throw PcapFsException("Invalid SMB2 Error Response Message");

                errorData.assign(&rawData.at(6), &rawData.at(6 + byteCount));
                totalSize = 8 + byteCount;
            }

            Bytes errorData;
        };

        class QueryInfoRequest : public SmbMessage {
        public:
            QueryInfoRequest(const uint8_t* data, size_t len) : SmbMessage(data, len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 41)
                    throw PcapFsException("Invalid StructureSize in SMB2 Query Info Request");

                const uint16_t inputBufferOffset = *(uint16_t*) &rawData.at(8);
                const uint32_t inputBufferLength = *(uint32_t*) &rawData.at(12);
                if (inputBufferOffset + inputBufferLength > len)
                    throw PcapFsException("Invalid buffer values in SMB2 Query Info Request");

                if (inputBufferOffset == 0 && inputBufferLength == 0)
                    totalSize = 41;
                else
                    totalSize = inputBufferOffset + inputBufferLength;
            }
        };

        class NegotiateRequest : public SmbMessage {
        public:
            NegotiateRequest(const uint8_t* data, size_t len) : SmbMessage(data, len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 36)
                    throw PcapFsException("Invalid StructureSize in SMB2 Negotiate Request");

                const uint16_t dialectCount = *(uint16_t*) &rawData.at(2);
                if (dialectCount > 5 || (size_t)(2*dialectCount + 36) > len)
                    throw PcapFsException("Invalid amount of dialects in SMB2 Negotiate Request");

                if (contains311Dialect(dialectCount)) {
                    const uint32_t negotiateContextOffset = *(uint32_t*) &rawData.at(28);
                    const uint16_t negotiateContextCount = *(uint32_t*) &rawData.at(32);
                    if (negotiateContextOffset + (8*negotiateContextCount) > len)
                        throw PcapFsException("Invalid negotiate context values in SMB2 Negotiate Request");

                    totalSize = calculate311NegotiateMessageLength(rawData, negotiateContextOffset, negotiateContextCount);
                } else {
                    totalSize = 36 + (2*dialectCount);
                }
            }

        private:
            bool contains311Dialect(uint16_t dialectCount) {
                for (int pos = 36; pos < 36 + (dialectCount*2) ; pos += 2) {
                    if (*(uint16_t*) &rawData.at(pos) == Version::SMB_VERSION_3_1_1)
                        return true;
                }
                return false;
            }

        };

        class NegotiateResponse : public SmbMessage {
        public:
            NegotiateResponse(const uint8_t* data, size_t len) : SmbMessage(data, len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 65)
                    throw PcapFsException("Invalid StructureSize in SMB2 Negotiate Response");

                dialect = *(uint16_t*) &rawData.at(4);
                if (dialect == Version::SMB_VERSION_3_1_1) {
                    const uint32_t negotiateContextOffset = *(uint32_t*) &rawData.at(60);
                    const uint16_t negotiateContextCount = *(uint32_t*) &rawData.at(6);
                    if (negotiateContextOffset + (8*negotiateContextCount) > len)
                        throw PcapFsException("Invalid negotiate context values in SMB2 Negotiate Response");

                    totalSize = calculate311NegotiateMessageLength(rawData, negotiateContextOffset, negotiateContextCount);
                } else {
                    const uint16_t securityBufferOffset = *(uint16_t*) &rawData.at(56);
                    const uint16_t securityBufferLength = *(uint16_t*) &rawData.at(58);
                    if (securityBufferOffset + securityBufferLength > len)
                        throw PcapFsException("Invalid buffer values in SMB2 Negotiate Response");

                    totalSize = securityBufferOffset + securityBufferLength;
                }
            }
            uint16_t dialect;
        };


        class SmbPacket {
        public:
            SmbPacket() {};
            SmbPacket(const uint8_t* data, size_t len);

            std::shared_ptr<SmbHeader> header = nullptr;
            SmbMessage message;
            size_t size = 0;
            bool isResponse = false;
            std::string command = "";
            uint8_t headerType = HeaderType::SMB2_PACKET_HEADER;

        private:
            std::string const commandToString(uint16_t cmdCode);
        };
    }
}

#endif //PCAPFS_SMB_MESSAGES_H
