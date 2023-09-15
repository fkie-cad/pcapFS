#include "smb_messages.h"
#include "smb_headers.h"


pcapfs::smb::SmbPacket::SmbPacket(const uint8_t* data, size_t len) {

    const uint32_t protocolId = *(uint32_t*) data;
    if (protocolId == 0x424D53FE) {
        // classic SMB2 packet header
        if (len < 64)
            throw PcapFsException("Invalid SMB2 Packet Header");

        std::shared_ptr<SmbPacketHeader> packetHeader = std::make_shared<SmbPacketHeader>(data);
        isResponse = packetHeader->flags & PacketHeaderFlags::SMB2_FLAGS_SERVER_TO_REDIR;
        if (isResponse && (packetHeader->status != StatusCodes::STATUS_SUCCESS)) {
            try{
                message = ErrorResponse(&data[64], len - 64);
            } catch (const PcapFsException &err) {
                // we don't have a correct Error Response Message and try the other message types in the switch
            }
        }
        try {
            switch (packetHeader->command) {
                case Command::SMB2_NEGOTIATE:
                    if (isResponse)
                        message = NegotiateResponse(&data[64], len - 64);
                    else
                        message = NegotiateRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_QUERY_INFO:
                    if (isResponse)
                        // TODO: change to QueryInfoResponse
                        message = SmbMessage(&data[64], len - 64);
                    else
                        message = QueryInfoRequest(&data[64], len - 64);
                    break;

                default:
                    message = SmbMessage(&data[64], len - 64);
            }
        } catch (const PcapFsException &err) {
            message = SmbMessage(&data[64], len - 64);
        }
        command = commandToString(packetHeader->command);
        size = 64 + message.totalSize;
        header = packetHeader;
        headerType = HeaderType::SMB2_PACKET_HEADER;

    } else if (protocolId == 0x424D53FD) {
        // transform header with encrypted message
        if (len < 52)
            throw PcapFsException("Invalid SMB2 Transform Header");

        std::shared_ptr<SmbTransformHeader> transformHeader = std::make_shared<SmbTransformHeader>(data);
        if (len < 52 + transformHeader->messageSize)
            throw PcapFsException("Invalid SMB2 Transform Header");

        message = SmbMessage(&data[52], transformHeader->messageSize);
        command = "Encrypted SMB3";
        size = 52 + message.totalSize;
        header = transformHeader;
        headerType = HeaderType::SMB2_TRANSFORM_HEADER;

    } else if (protocolId == 0x424D53FC) {
        // compression transform header
        if (len < 16)
            throw PcapFsException("Invalid SMB2 Compression Transform Header");

        command = "Compressed SMB3";
        SmbCompressionTransformHeader compressionTransformHeader(data);
        if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_NONE) {
            std::shared_ptr<SmbCompressionTransformHeaderUnchained> compressionTransformHeaderUnchained =
                    std::make_shared<SmbCompressionTransformHeaderUnchained>(data);
            if (16 + compressionTransformHeaderUnchained->offset > len)
                throw PcapFsException("Invalid SMB2 Compression Transform Header");

            message = SmbMessage(&data[16 + compressionTransformHeaderUnchained->offset],
                                    len - (16 + compressionTransformHeaderUnchained->offset));
            size = 16 + compressionTransformHeaderUnchained->offset + message.totalSize;
            header = compressionTransformHeaderUnchained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED;

        } else if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_CHAINED) {
            std::shared_ptr<SmbCompressionTransformHeaderChained> compressionTransformHeaderChained =
                    std::make_shared<SmbCompressionTransformHeaderChained>(data);

            if (16 + compressionTransformHeaderChained->length > len)
                throw PcapFsException("Invalid SMB2 Compression Transform Header");

            if (compressionTransformHeaderChained->usesOriginalPayloadSizeField()) {
                message = SmbMessage(&data[16 + 4], compressionTransformHeaderChained->length - 4);
                size = 16 + 4 + message.totalSize;
            } else {
                message = SmbMessage(&data[16], compressionTransformHeaderChained->length);
                size = 16 + message.totalSize;
            }

            header = compressionTransformHeaderChained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED;
        } else
            throw PcapFsException("Invalid SMB2 Packet Header");

    } else
        throw PcapFsException("Invalid SMB2 Packet Header");
}


std::string const pcapfs::smb::SmbPacket::commandToString(uint16_t cmdCode) {
    std::string result = cmdCode <= 0x12 ? smbCommandStrings[cmdCode] : "SMB2 UNKNOWN";
    result.append(isResponse ? " Response" : " Request");
    return result;
}
