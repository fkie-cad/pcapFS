#include "smb_messages.h"
#include "smb_headers.h"
#include "../../logging.h"

#include <sstream>
#include <iomanip>

pcapfs::smb::SmbPacket::SmbPacket(const uint8_t* data, size_t len, SmbContextPtr &smbContext) {

    const uint32_t protocolId = *(uint32_t*) data;
    if (protocolId == 0x424D53FE) {
        // classic SMB2 packet header
        if (len < 64)
            throw SmbError("Invalid SMB2 Packet Header");

        std::shared_ptr<SmbPacketHeader> packetHeader = std::make_shared<SmbPacketHeader>(data);
        isResponse = packetHeader->flags & PacketHeaderFlags::SMB2_FLAGS_SERVER_TO_REDIR;
        try {
            switch (packetHeader->command) {
                case Commands::SMB2_NEGOTIATE:
                    if (isResponse) {
                        std::shared_ptr<NegotiateResponse> negResponse =
                                std::make_shared<NegotiateResponse>(&data[64], len - 64);
                        smbContext->dialect = negResponse->dialect;
                        message = negResponse;
                    } else
                        message = std::make_shared<NegotiateRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_SESSION_SETUP:
                    if (isResponse)
                        message = std::make_shared<SessionSetupResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<SessionSetupRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_TREE_CONNECT:
                    if (isResponse)
                        message = std::make_shared<TreeConnectResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<TreeConnectRequest>(&data[64], len - 64, smbContext->dialect);
                    break;

                case Commands::SMB2_CREATE:
                    if (isResponse) {
                        std::shared_ptr<CreateResponse> createResponse =
                                std::make_shared<CreateResponse>(&data[64], len - 64);
                        smbContext->fileHandles[createResponse->fileId] = smbContext->currentRequestedFile;
                        message = createResponse;
                    } else {
                        std::shared_ptr<CreateRequest> createRequest =
                                std::make_shared<CreateRequest>(&data[64], len - 64);
                        smbContext->currentRequestedFile = createRequest->filename;
                        message = createRequest;
                    }
                    break;

                case Commands::SMB2_CLOSE:
                    if (isResponse)
                        message = std::make_shared<CloseResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<CloseRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_FLUSH:
                    if (isResponse)
                        message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    else
                        message = std::make_shared<FlushRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_READ:
                    if (isResponse)
                        message = std::make_shared<ReadResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<ReadRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_WRITE:
                    if (isResponse)
                        message = std::make_shared<WriteResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<WriteRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_OPLOCK_BREAK:
                    message = std::make_shared<OplockBreakMessage>(&data[64], len - 64);
                    break;

                case Commands::SMB2_LOCK:
                    if (isResponse)
                        message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    else
                        message = std::make_shared<LockRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_IOCTL:
                    if (isResponse)
                        message = std::make_shared<IoctlResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<IoctlRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_QUERY_DIRECTORY:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryDirectoryResponse and Error Response are the same
                            message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = std::make_shared<QueryDirectoryResponse>(&data[64], len - 64);
                    } else
                        message = std::make_shared<QueryDirectoryRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_CHANGE_NOTIFY:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // ChangeNotifyResponse and Error Response are the same
                            message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = std::make_shared<ChangeNotifyResponse>(&data[64], len - 64);
                    } else
                        message = std::make_shared<ChangeNotifyRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_QUERY_INFO:
                    if (isResponse)
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryInfoResponse and Error Response are the same
                            message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            message = std::make_shared<QueryInfoResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<QueryInfoRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_SET_INFO:
                    if (isResponse)
                        message = std::make_shared<SetInfoResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<SetInfoRequest>(&data[64], len - 64);
                    break;

                case Commands::SMB2_LOGOFF:
                case Commands::SMB2_TREE_DISCONNECT:
                case Commands::SMB2_ECHO:
                case Commands::SMB2_CANCEL:
                    message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    break;

                default:
                    message = std::make_shared<SmbMessage>(&data[64], len - 64);
                    parsingFailed = true;
            }
        } catch (const SmbSizeError &err) {
            if (isResponse && packetHeader->status != StatusCodes::STATUS_SUCCESS &&
                *(uint16_t*) &data[64] == 9) {
                // we probably have an error response because of structureSize 9 and
                // no STATUS_SUCCESS
                try {
                    message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                    isErrorResponse = true;
                } catch (const SmbError &smbErr) {
                    LOG_WARNING << "Failed to parse SMB2 Message: " << smbErr.what();
                    message = std::make_shared<SmbMessage>(&data[64], len - 64);
                    parsingFailed = true;
                }
            } else {
                LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
                message = std::make_shared<SmbMessage>(&data[64], len - 64);
                parsingFailed = true;
            }

        } catch (const SmbError &err) {
            LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
            message = std::make_shared<SmbMessage>(&data[64], len - 64);
            parsingFailed = true;
        }
        size = 64 + message->totalSize;
        header = packetHeader;
        headerType = HeaderType::SMB2_PACKET_HEADER;

    } else if (protocolId == 0x424D53FD) {
        // transform header with encrypted message
        if (len < 52)
            throw SmbError("Invalid SMB2 Transform Header");

        std::shared_ptr<SmbTransformHeader> transformHeader = std::make_shared<SmbTransformHeader>(data);
        if (len < 52 + transformHeader->messageSize)
            throw SmbError("Invalid SMB2 Transform Header");

        message = std::make_shared<SmbMessage>(&data[52], transformHeader->messageSize);
        size = 52 + message->totalSize;
        header = transformHeader;
        headerType = HeaderType::SMB2_TRANSFORM_HEADER;

    } else if (protocolId == 0x424D53FC) {
        // compression transform header
        if (len < 16)
            throw SmbError("Invalid SMB2 Compression Transform Header");

        const SmbCompressionTransformHeader compressionTransformHeader(data);
        if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_NONE) {
            std::shared_ptr<SmbCompressionTransformHeaderUnchained> compressionTransformHeaderUnchained =
                    std::make_shared<SmbCompressionTransformHeaderUnchained>(data);
            if (16 + compressionTransformHeaderUnchained->offset > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

            message = std::make_shared<SmbMessage>(&data[16 + compressionTransformHeaderUnchained->offset],
                                    len - (16 + compressionTransformHeaderUnchained->offset));
            size = 16 + compressionTransformHeaderUnchained->offset + message->totalSize;
            header = compressionTransformHeaderUnchained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED;

        } else if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_CHAINED) {
            std::shared_ptr<SmbCompressionTransformHeaderChained> compressionTransformHeaderChained =
                    std::make_shared<SmbCompressionTransformHeaderChained>(data);

            if (16 + compressionTransformHeaderChained->length > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

            if (compressionTransformHeaderChained->usesOriginalPayloadSizeField()) {
                message = std::make_shared<SmbMessage>(&data[16 + 4], compressionTransformHeaderChained->length - 4);
                size = 16 + 4 + message->totalSize;
            } else {
                message = std::make_shared<SmbMessage>(&data[16], compressionTransformHeaderChained->length);
                size = 16 + message->totalSize;
            }

            header = compressionTransformHeaderChained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED;
        } else
            throw SmbError("Invalid SMB2 Packet Header");

    } else {
        throw SmbError("Invalid SMB2 Packet Header");
    }
}


std::string const pcapfs::smb::SmbPacket::toString(const SmbContextPtr &smbContext) {
    std::stringstream ss;
    if (headerType == HeaderType::SMB2_PACKET_HEADER) {
        std::shared_ptr<SmbPacketHeader> packetHeader = std::static_pointer_cast<SmbPacketHeader>(header);
        if (isResponse) {
            ss << "[<] " << commandToString(packetHeader->command);
            if (!parsingFailed && !isErrorResponse) {
                switch (packetHeader->command) {
                    case Commands::SMB2_CREATE:
                        {
                           const std::shared_ptr<CreateResponse> msg = std::static_pointer_cast<CreateResponse>(message);
                            ss << ", Action: " << createActionStrings.at(msg->createAction);
                        }
                        break;
                }
            }
            if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                if (statusCodeStrings.find(packetHeader->status) != statusCodeStrings.end())
                    ss << ", Error: " << statusCodeStrings.at(packetHeader->status);
                else
                    ss << ", Error: " << "UNKNOWN_ERROR " << "0x" << std::hex << std::setfill('0') << std::setw(2) << packetHeader->status;
            }
        } else {
            // Request
            ss << "[>] " << commandToString(packetHeader->command);
            if (!parsingFailed) {
                switch (packetHeader->command) {
                    case Commands::SMB2_TREE_CONNECT:
                        {
                            const std::shared_ptr<TreeConnectRequest> msg = std::static_pointer_cast<TreeConnectRequest>(message);
                            ss << ", Tree: " << msg->pathName;
                        }
                        break;

                    case Commands::SMB2_CREATE:
                        {
                            const std::shared_ptr<CreateRequest> msg = std::static_pointer_cast<CreateRequest>(message);
                            if (!msg->filename.empty())
                                ss << ", File: " << msg->filename;
                            ss << ", Mode: " << createDispositionStrings.at(msg->disposition);
                        }
                        break;

                    case Commands::SMB2_CLOSE:
                        {
                            const std::shared_ptr<CloseRequest> msg = std::static_pointer_cast<CloseRequest>(message);
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_READ:
                        {
                            const std::shared_ptr<ReadRequest> msg = std::static_pointer_cast<ReadRequest>(message);
                            ss << ", Off: " << msg->readOffset << ", Len: " << msg->readLength;
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_WRITE:
                        {
                            const std::shared_ptr<WriteRequest> msg = std::static_pointer_cast<WriteRequest>(message);
                            ss << ", Off: " << msg->writeOffset << ", Len: " << msg->writeLength;
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_QUERY_DIRECTORY:
                        {
                            const std::shared_ptr<QueryDirectoryRequest> msg = std::static_pointer_cast<QueryDirectoryRequest>(message);
                            ss << ", " << fileInfoClassStrings.at(msg->fileInfoClass) << ", Search Pattern: " << msg->searchPattern;
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_QUERY_INFO:
                        {
                            const std::shared_ptr<QueryInfoRequest> msg = std::static_pointer_cast<QueryInfoRequest>(message);
                            ss << ", " << queryInfoTypeStrings.at(msg->infoType);
                            if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILE)
                                ss << "/" << fileInfoClassStrings.at(msg->fileInfoClass);
                            else if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM)
                                ss << "/" << fsInfoClassStrings.at(msg->fileInfoClass);
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_IOCTL:
                        {
                            const std::shared_ptr<IoctlRequest> msg = std::static_pointer_cast<IoctlRequest>(message);
                            ss << ", " << ctlCodeStrings.at(msg->ctlCode);
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;

                    case Commands::SMB2_SET_INFO:
                        {
                            const std::shared_ptr<SetInfoRequest> msg = std::static_pointer_cast<SetInfoRequest>(message);
                            ss << ", " << queryInfoTypeStrings.at(msg->infoType);
                            if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILE)
                                ss << "/" << fileInfoClassStrings.at(msg->fileInfoClass);
                            else if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM)
                                ss << "/" << fsInfoClassStrings.at(msg->fileInfoClass);
                            if (smbContext->fileHandles.find(msg->fileId) != smbContext->fileHandles.end() &&
                                !smbContext->fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << smbContext->fileHandles.at(msg->fileId);
                        }
                        break;
                }
            }
        }
    } else if (headerType == HeaderType::SMB2_TRANSFORM_HEADER) {
        ss << "[<|>] " << "Encrypted SMB3";
    } else {
        ss << "[<|>] " << "Compressed SMB3";
    }
    ss << std::endl;
    return ss.str();
}


std::string const pcapfs::smb::SmbPacket::commandToString(uint16_t cmdCode) {
    std::string result = cmdCode <= 0x12 ? smbCommandStrings.at(cmdCode) : "SMB2 UNKNOWN";
    if (cmdCode == Commands::SMB2_OPLOCK_BREAK)
        result.append(" Message");
    else
        result.append(isResponse ? " Response" : " Request");
    return result;
}
