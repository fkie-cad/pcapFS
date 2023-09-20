#include "smb_messages.h"
#include "smb_headers.h"
#include "../../logging.h"


pcapfs::smb::SmbPacket::SmbPacket(const uint8_t* data, size_t len, uint16_t dial) {

    dialect = dial;
    const uint32_t protocolId = *(uint32_t*) data;
    if (protocolId == 0x424D53FE) {
        // classic SMB2 packet header
        if (len < 64)
            throw SmbError("Invalid SMB2 Packet Header");

        std::shared_ptr<SmbPacketHeader> packetHeader = std::make_shared<SmbPacketHeader>(data);
        isResponse = packetHeader->flags & PacketHeaderFlags::SMB2_FLAGS_SERVER_TO_REDIR;
        try {
            switch (packetHeader->command) {
                case Command::SMB2_NEGOTIATE:
                    if (isResponse) {
                        NegotiateResponse negResponse(&data[64], len - 64);
                        dialect = negResponse.dialect;
                        message = negResponse;
                    } else
                        message = NegotiateRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_SESSION_SETUP:
                    if (isResponse)
                        message = SessionSetupResponse(&data[64], len - 64);
                    else
                        message = SessionSetupRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_TREE_CONNECT:
                    if (isResponse)
                        message = TreeConnectResponse(&data[64], len - 64);
                    else
                        message = TreeConnectRequest(&data[64], len - 64, dialect);
                    break;

                case Command::SMB2_CREATE:
                    if (isResponse)
                        message = CreateResponse(&data[64], len - 64);
                    else
                        message = CreateRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_CLOSE:
                    if (isResponse)
                        message = CloseResponse(&data[64], len - 64);
                    else
                        message = CloseRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_FLUSH:
                    if (isResponse)
                        message = FourByteMessage(&data[64], len - 64);
                    else
                        message = FlushRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_READ:
                    if (isResponse)
                        message = ReadResponse(&data[64], len - 64);
                    else
                        message = ReadRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_WRITE:
                    if (isResponse)
                        message = WriteResponse(&data[64], len - 64);
                    else
                        message = WriteRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_OPLOCK_BREAK:
                    message = OplockBreakMessage(&data[64], len - 64);
                    break;

                case Command::SMB2_LOCK:
                    if (isResponse)
                        message = FourByteMessage(&data[64], len - 64);
                    else
                        message = LockRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_IOCTL:
                    if (isResponse)
                        message = IoctlResponse(&data[64], len - 64);
                    else
                        message = IoctlRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_QUERY_DIRECTORY:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryDirectoryResponse and Error Response are the same
                            message = ErrorResponse(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = QueryDirectoryResponse(&data[64], len - 64);
                    } else
                        message = QueryDirectoryRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_CHANGE_NOTIFY:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // ChangeNotifyResponse and Error Response are the same
                            message = ErrorResponse(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = ChangeNotifyResponse(&data[64], len - 64);
                    } else
                        message = ChangeNotifyRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_QUERY_INFO:
                    if (isResponse)
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryInfoResponse and Error Response are the same
                            message = ErrorResponse(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = QueryInfoResponse(&data[64], len - 64);
                    else
                        message = QueryInfoRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_SET_INFO:
                    if (isResponse)
                        message = SetInfoResponse(&data[64], len - 64);
                    else
                        message = SetInfoRequest(&data[64], len - 64);
                    break;

                case Command::SMB2_LOGOFF:
                case Command::SMB2_TREE_DISCONNECT:
                case Command::SMB2_ECHO:
                case Command::SMB2_CANCEL:
                    message = FourByteMessage(&data[64], len - 64);
                    break;

                default:
                    message = SmbMessage(&data[64], len - 64);
                    parsingFailed = true;
            }
        } catch (const SmbSizeError &err) {
            if (isResponse && packetHeader->status != StatusCodes::STATUS_SUCCESS &&
                *(uint16_t*) &data[64] == 9) {
                // we probably have an error response because of structureSize 9 and
                // no STATUS_SUCCESS
                try {
                    message = ErrorResponse(&data[64], len - 64);
                    isErrorResponse = true;
                } catch (const SmbError &smbErr) {
                    LOG_WARNING << "Failed to parse SMB2 Message: " << smbErr.what();
                    message = SmbMessage(&data[64], len - 64);
                    parsingFailed = true;
                }
            } else {
                LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
                message = SmbMessage(&data[64], len - 64);
                parsingFailed = true;
            }

        } catch (const SmbError &err) {
            LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
            message = SmbMessage(&data[64], len - 64);
            parsingFailed = true;
        }
        command = commandToString(packetHeader->command);
        size = 64 + message.totalSize;
        header = packetHeader;
        headerType = HeaderType::SMB2_PACKET_HEADER;

    } else if (protocolId == 0x424D53FD) {
        // transform header with encrypted message
        if (len < 52)
            throw SmbError("Invalid SMB2 Transform Header");

        std::shared_ptr<SmbTransformHeader> transformHeader = std::make_shared<SmbTransformHeader>(data);
        if (len < 52 + transformHeader->messageSize)
            throw SmbError("Invalid SMB2 Transform Header");

        message = SmbMessage(&data[52], transformHeader->messageSize);
        command = "Encrypted SMB3";
        size = 52 + message.totalSize;
        header = transformHeader;
        headerType = HeaderType::SMB2_TRANSFORM_HEADER;

    } else if (protocolId == 0x424D53FC) {
        // compression transform header
        if (len < 16)
            throw SmbError("Invalid SMB2 Compression Transform Header");

        command = "Compressed SMB3";
        const SmbCompressionTransformHeader compressionTransformHeader(data);
        if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_NONE) {
            std::shared_ptr<SmbCompressionTransformHeaderUnchained> compressionTransformHeaderUnchained =
                    std::make_shared<SmbCompressionTransformHeaderUnchained>(data);
            if (16 + compressionTransformHeaderUnchained->offset > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

            message = SmbMessage(&data[16 + compressionTransformHeaderUnchained->offset],
                                    len - (16 + compressionTransformHeaderUnchained->offset));
            size = 16 + compressionTransformHeaderUnchained->offset + message.totalSize;
            header = compressionTransformHeaderUnchained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED;

        } else if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_CHAINED) {
            std::shared_ptr<SmbCompressionTransformHeaderChained> compressionTransformHeaderChained =
                    std::make_shared<SmbCompressionTransformHeaderChained>(data);

            if (16 + compressionTransformHeaderChained->length > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

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
            throw SmbError("Invalid SMB2 Packet Header");

    } else {
        throw SmbError("Invalid SMB2 Packet Header");
    }
}


std::string const pcapfs::smb::SmbPacket::commandToString(uint16_t cmdCode) {
    std::string result = cmdCode <= 0x12 ? smbCommandStrings.at(cmdCode) : "SMB2 UNKNOWN";
    if (cmdCode == Command::SMB2_OPLOCK_BREAK)
        result.append(" Message");
    else
        result.append(isResponse ? " Response" : " Request");
    return result;
}
