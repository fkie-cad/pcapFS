#include "smb_packet.h"
#include "smb_manager.h"
#include "../../logging.h"
#include <sstream>
#include <iomanip>


pcapfs::smb::SmbPacket::SmbPacket(const uint8_t* data, size_t len, SmbContextPtr &smbContext) {

    const uint32_t protocolId = *(uint32_t*) data;
    if (protocolId == ProtocolId::SMB2_PACKET_HEADER_ID) {
        // classic SMB2 packet header
        if (len < 64)
            throw SmbError("Invalid SMB2 Packet Header");

        const std::shared_ptr<Smb2Header> packetHeader = std::make_shared<Smb2Header>(data);
        if (!(packetHeader->flags & Smb2HeaderFlags::SMB2_FLAGS_ASYNC_COMMAND)) {
            // TODO: could this lead to errors/bugs?
            smbContext->currentTreeId = packetHeader->treeId;
        }

        smbContext->serverEndpoint.sessionId = packetHeader->sessionId;
        isResponse = packetHeader->flags & Smb2HeaderFlags::SMB2_FLAGS_SERVER_TO_REDIR;
        LOG_TRACE << "found SMB2 packet with message type " << packetHeader->command << (isResponse ? " (Response)" : " (Request)");
        try {
            switch (packetHeader->command) {
                case Smb2Commands::SMB2_NEGOTIATE:
                    if (isResponse) {
                        const std::shared_ptr<NegotiateResponse> negResponse = std::make_shared<NegotiateResponse>(&data[64], len - 64);
                        smbContext->dialect = negResponse->dialect;
                        message = negResponse;
                    } else
                        message = std::make_shared<NegotiateRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_SESSION_SETUP:
                    if (isResponse)
                        message = std::make_shared<SessionSetupResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<SessionSetupRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_TREE_CONNECT:
                    if (isResponse)
                        message = std::make_shared<TreeConnectResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<TreeConnectRequest>(&data[64], len - 64, smbContext->dialect);
                    break;

                case Smb2Commands::SMB2_CREATE:
                    if (isResponse) {
                        const std::shared_ptr<CreateResponse> createResponse = std::make_shared<CreateResponse>(&data[64], len - 64);
                        if (smbContext->createServerFiles &&
                            smbContext->createRequestFileNames.find(packetHeader->messageId) != smbContext->createRequestFileNames.end() &&
                            !smbContext->createRequestFileNames.at(packetHeader->messageId).empty())
                            SmbManager::getInstance().updateSmbFiles(createResponse, smbContext, packetHeader->messageId);
                        message = createResponse;
                    } else {
                        const std::shared_ptr<CreateRequest> createRequest = std::make_shared<CreateRequest>(&data[64], len - 64);
                        LOG_TRACE << "create request file: " << createRequest->filename;
                        smbContext->createRequestFileNames[packetHeader->messageId] = createRequest->filename;
                        message = createRequest;
                    }
                    break;

                case Smb2Commands::SMB2_CLOSE:
                    if (isResponse) {
                        message = std::make_shared<CloseResponse>(&data[64], len - 64);
                    } else
                        message = std::make_shared<CloseRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_FLUSH:
                    if (isResponse)
                        message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    else
                        message = std::make_shared<FlushRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_READ:
                    if (isResponse) {
                        if (smbContext->createServerFiles &&
                            smbContext->readRequestData.find(packetHeader->messageId) != smbContext->readRequestData.end() &&
                            smbContext->readRequestData[packetHeader->messageId]) {

                            const std::shared_ptr<ReadResponse> readResponse = std::make_shared<ReadResponse>(&data[64], len - 64);
                            if (readResponse->dataLength != 0)
                                SmbManager::getInstance().updateSmbFiles(readResponse, smbContext, packetHeader->messageId);
                            message = readResponse;
                        } else {
                            message = std::make_shared<ReadResponse>(&data[64], len - 64);
                        }
                    } else {
                        const std::shared_ptr<ReadRequest> readRequest = std::make_shared<ReadRequest>(&data[64], len - 64);
                        std::shared_ptr<ReadRequestData> newReadRequestData = std::make_shared<ReadRequestData>();
                        newReadRequestData->fileId = readRequest->fileId;
                        newReadRequestData->readOffset = readRequest->readOffset;
                        smbContext->readRequestData[packetHeader->messageId] = newReadRequestData;
                        message = readRequest;
                    }
                    break;

                case Smb2Commands::SMB2_WRITE:
                    if (isResponse)
                        message = std::make_shared<WriteResponse>(&data[64], len - 64);
                    else {
                        const std::shared_ptr<WriteRequest> writeRequest = std::make_shared<WriteRequest>(&data[64], len - 64);
                        // we don't care whether the write was successful at the end or not
                        if (smbContext->createServerFiles && writeRequest->writeLength != 0)
                            SmbManager::getInstance().updateSmbFiles(writeRequest, smbContext);
                        message = writeRequest;
                    }
                    break;

                case Smb2Commands::SMB2_OPLOCK_BREAK:
                    message = std::make_shared<OplockBreakMessage>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_LOCK:
                    if (isResponse)
                        message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    else
                        message = std::make_shared<LockRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_IOCTL:
                    if (isResponse)
                        message = std::make_shared<IoctlResponse>(&data[64], len - 64);
                    else
                        message = std::make_shared<IoctlRequest>(&data[64], len - 64);
                    break;

                case Smb2Commands::SMB2_QUERY_DIRECTORY:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryDirectoryResponse and Error Response are the same
                            message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                            isErrorResponse = true;
                        } else
                            if (smbContext->queryDirectoryRequestData.find(packetHeader->messageId) != smbContext->queryDirectoryRequestData.end() &&
                                smbContext->queryDirectoryRequestData[packetHeader->messageId]) {
                                const std::shared_ptr<QueryDirectoryResponse> queryDirectoryResponse =
                                        std::make_shared<QueryDirectoryResponse>(&data[64], len - 64,
                                            smbContext->queryDirectoryRequestData[packetHeader->messageId]->fileInfoClass);

                                if (smbContext->createServerFiles && !queryDirectoryResponse->fileInfos.empty())
                                    SmbManager::getInstance().updateSmbFiles(queryDirectoryResponse->fileInfos, smbContext, packetHeader->messageId);

                                smbContext->queryDirectoryRequestData.erase(packetHeader->messageId);
                                message = queryDirectoryResponse;
                            } else {
                                message = std::make_shared<QueryDirectoryResponse>(&data[64], len - 64, FileInfoClass::FILE_UNKNOWN_INFORMATION);
                            }
                    } else {
                        const std::shared_ptr<QueryDirectoryRequest> queryDirectoryRequest = std::make_shared<QueryDirectoryRequest>(&data[64], len - 64);
                        const std::shared_ptr<QueryDirectoryRequestData> queryDirectoryRequestData = std::make_shared<QueryDirectoryRequestData>();
                        LOG_TRACE << "requested information: " << fileInfoClassStrings.at(queryDirectoryRequest->fileInfoClass);
                        queryDirectoryRequestData->fileInfoClass = queryDirectoryRequest->fileInfoClass;
                        queryDirectoryRequestData->fileId = queryDirectoryRequest->fileId;
                        smbContext->queryDirectoryRequestData[packetHeader->messageId] = queryDirectoryRequestData;
                        message = queryDirectoryRequest;
                    }
                    break;

                case Smb2Commands::SMB2_CHANGE_NOTIFY:
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

                case Smb2Commands::SMB2_QUERY_INFO:
                    if (isResponse) {
                        if (packetHeader->status != StatusCodes::STATUS_SUCCESS) {
                            // probably an error response
                            // we need to handle it here because the structureSizes of
                            // QueryInfoResponse and Error Response are the same
                            message = std::make_shared<ErrorResponse>(&data[64], len - 64);
                            isErrorResponse = true;
                        } else {
                            if (smbContext->queryInfoRequestData.find(packetHeader->messageId) != smbContext->queryInfoRequestData.end() &&
                                smbContext->queryInfoRequestData[packetHeader->messageId]) {
                                const std::shared_ptr<QueryInfoResponse> queryInfoResponse =
                                        std::make_shared<QueryInfoResponse>(&data[64], len - 64,
                                            smbContext->queryInfoRequestData[packetHeader->messageId]);

                                if (queryInfoResponse->metaData)
                                    SmbManager::getInstance().updateSmbFiles(queryInfoResponse, smbContext, packetHeader->messageId);

                                smbContext->queryInfoRequestData.erase(packetHeader->messageId);
                                message = queryInfoResponse;
                            } else {
                                message = std::make_shared<QueryInfoResponse>(&data[64], len - 64, nullptr);
                            }
                        }
                    } else {
                        const std::shared_ptr<QueryInfoRequest> queryInfoRequest = std::make_shared<QueryInfoRequest>(&data[64], len - 64);
                        std::shared_ptr<QueryInfoRequestData> queryInfoRequestData = std::make_shared<QueryInfoRequestData>();
                        LOG_TRACE << "requested information: " << queryInfoTypeStrings.at(queryInfoRequest->infoType);
                        queryInfoRequestData->infoType = queryInfoRequest->infoType;
                        queryInfoRequestData->fileInfoClass = queryInfoRequest->fileInfoClass;
                        queryInfoRequestData->fileId = queryInfoRequest->fileId;
                        smbContext->queryInfoRequestData[packetHeader->messageId] = queryInfoRequestData;
                        message = queryInfoRequest;
                    }
                    break;

                case Smb2Commands::SMB2_SET_INFO:
                    if (isResponse) {
                        if (packetHeader->status == StatusCodes::STATUS_SUCCESS &&
                            smbContext->setInfoRequestData.find(packetHeader->messageId) != smbContext->setInfoRequestData.end() &&
                            smbContext->setInfoRequestData[packetHeader->messageId]) {
                                SmbManager::getInstance().updateSmbFiles(smbContext, packetHeader->messageId);
                                smbContext->queryInfoRequestData.erase(packetHeader->messageId);
                        }
                        message = std::make_shared<SetInfoResponse>(&data[64], len - 64);

                    } else {
                        const std::shared_ptr<SetInfoRequest> setInfoRequest = std::make_shared<SetInfoRequest>(&data[64], len - 64);
                        if (setInfoRequest->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION) {
                            std::shared_ptr<SetInfoRequestData> setInfoRequestData = std::make_shared<SetInfoRequestData>();
                            setInfoRequestData->fileId = setInfoRequest->fileId;
                            setInfoRequestData->metaData = setInfoRequest->metaData;
                            smbContext->setInfoRequestData[packetHeader->messageId] = setInfoRequestData;
                        }
                        message = setInfoRequest;
                    }
                    break;

                case Smb2Commands::SMB2_LOGOFF:
                case Smb2Commands::SMB2_TREE_DISCONNECT:
                case Smb2Commands::SMB2_ECHO:
                case Smb2Commands::SMB2_CANCEL:
                    message = std::make_shared<FourByteMessage>(&data[64], len - 64);
                    break;

                default:
                    message = std::make_shared<SmbMessage>(len - 64);
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
                    message = std::make_shared<SmbMessage>(len - 64);
                    parsingFailed = true;
                }
            } else {
                LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
                message = std::make_shared<SmbMessage>(len - 64);
                parsingFailed = true;
            }

        } catch (const SmbError &err) {
            LOG_WARNING << "Failed to parse SMB2 Message: " << err.what();
            message = std::make_shared<SmbMessage>(len - 64);
            parsingFailed = true;
        }
        size = 64 + message->totalSize;
        header = packetHeader;
        headerType = HeaderType::SMB2_PACKET_HEADER;

    } else if (protocolId == ProtocolId::SMB2_TRANSFORM_HEADER_ID) {
        // transform header with encrypted message
        if (len < 52)
            throw SmbError("Invalid SMB2 Transform Header");

        std::shared_ptr<SmbTransformHeader> transformHeader = std::make_shared<SmbTransformHeader>(data);
        if (len < 52 + transformHeader->messageSize)
            throw SmbError("Invalid SMB2 Transform Header");

        message = std::make_shared<SmbMessage>(transformHeader->messageSize);
        size = 52 + message->totalSize;
        header = transformHeader;
        headerType = HeaderType::SMB2_TRANSFORM_HEADER;

    } else if (protocolId == ProtocolId::SMB2_COMPRESSION_TRANSFORM_HEADER_ID) {
        // compression transform header
        if (len < 16)
            throw SmbError("Invalid SMB2 Compression Transform Header");

        const SmbCompressionTransformHeader compressionTransformHeader(data);
        if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_NONE) {
            const std::shared_ptr<SmbCompressionTransformHeaderUnchained> compressionTransformHeaderUnchained =
                    std::make_shared<SmbCompressionTransformHeaderUnchained>(data);
            if (16 + compressionTransformHeaderUnchained->offset > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

            message = std::make_shared<SmbMessage>(len - (16 + compressionTransformHeaderUnchained->offset));
            size = 16 + compressionTransformHeaderUnchained->offset + message->totalSize;
            header = compressionTransformHeaderUnchained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED;

        } else if (compressionTransformHeader.flags == CompressionFlags::SMB2_COMPRESSION_FLAG_CHAINED) {
            const std::shared_ptr<SmbCompressionTransformHeaderChained> compressionTransformHeaderChained =
                    std::make_shared<SmbCompressionTransformHeaderChained>(data);

            if (16 + compressionTransformHeaderChained->length > len)
                throw SmbError("Invalid SMB2 Compression Transform Header");

            if (compressionTransformHeaderChained->usesOriginalPayloadSizeField()) {
                message = std::make_shared<SmbMessage>(compressionTransformHeaderChained->length - 4);
                size = 16 + 4 + message->totalSize;
            } else {
                message = std::make_shared<SmbMessage>(compressionTransformHeaderChained->length);
                size = 16 + message->totalSize;
            }

            header = compressionTransformHeaderChained;
            headerType = HeaderType::SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED;

        } else
            throw SmbError("Invalid SMB2 Packet Header");

    } else if (protocolId == ProtocolId::SMB1_PACKET_HEADER_ID) {
        // SMB version 1 header
        if (len < 32)
            throw SmbError("Invalid SMB Packet Header");

        const std::shared_ptr<Smb1Header> packetHeader = std::make_shared<Smb1Header>(data);
        isResponse = packetHeader->flags & Smb1HeaderFlags::SMB_FLAGS_REPLY;
        header = packetHeader;
        headerType = HeaderType::SMB1_PACKET_HEADER;
        message = std::make_shared<SmbMessage>(len - 32);
        size = 32 + message->totalSize;

    } else {
        throw SmbError("Invalid SMB2 Packet Header");
    }
}


std::string const pcapfs::smb::SmbPacket::toString(const SmbContextPtr &smbContext) {
    std::stringstream ss;
    if (headerType == HeaderType::SMB2_PACKET_HEADER) {
        std::shared_ptr<Smb2Header> packetHeader = std::static_pointer_cast<Smb2Header>(header);
        if (isResponse) {
            ss << "[<] " << smb2CommandToString(packetHeader->command);
            if (!parsingFailed && !isErrorResponse) {
                switch (packetHeader->command) {
                    case Smb2Commands::SMB2_CREATE:
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
            ss << "[>] " << smb2CommandToString(packetHeader->command);
            if (!parsingFailed) {
                const SmbFileHandles fileHandles = SmbManager::getInstance().getFileHandles(smbContext);
                switch (packetHeader->command) {
                    case Smb2Commands::SMB2_TREE_CONNECT:
                        {
                            const std::shared_ptr<TreeConnectRequest> msg = std::static_pointer_cast<TreeConnectRequest>(message);
                            ss << ", Tree: " << msg->pathName;
                        }
                        break;

                    case Smb2Commands::SMB2_CREATE:
                        {
                            const std::shared_ptr<CreateRequest> msg = std::static_pointer_cast<CreateRequest>(message);
                            if (!msg->filename.empty())
                                ss << ", File: " << msg->filename;
                            ss << ", Mode: " << createDispositionStrings.at(msg->disposition);
                        }
                        break;

                    case Smb2Commands::SMB2_CLOSE:
                        {
                            const std::shared_ptr<CloseRequest> msg = std::static_pointer_cast<CloseRequest>(message);
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_READ:
                        {
                            const std::shared_ptr<ReadRequest> msg = std::static_pointer_cast<ReadRequest>(message);
                            ss << ", Off: " << msg->readOffset << ", Len: " << msg->readLength;
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_WRITE:
                        {
                            const std::shared_ptr<WriteRequest> msg = std::static_pointer_cast<WriteRequest>(message);
                            ss << ", Off: " << msg->writeOffset << ", Len: " << msg->writeLength;
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_QUERY_DIRECTORY:
                        {
                            const std::shared_ptr<QueryDirectoryRequest> msg = std::static_pointer_cast<QueryDirectoryRequest>(message);
                            ss << ", " << fileInfoClassStrings.at(msg->fileInfoClass) << ", Search Pattern: " << msg->searchPattern;
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_QUERY_INFO:
                        {
                            const std::shared_ptr<QueryInfoRequest> msg = std::static_pointer_cast<QueryInfoRequest>(message);
                            ss << ", " << queryInfoTypeStrings.at(msg->infoType);
                            if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILE)
                                ss << "/" << fileInfoClassStrings.at(msg->fileInfoClass);
                            else if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM)
                                ss << "/" << fsInfoClassStrings.at(msg->fileInfoClass);
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_IOCTL:
                        {
                            const std::shared_ptr<IoctlRequest> msg = std::static_pointer_cast<IoctlRequest>(message);
                            ss << ", " << ctlCodeStrings.at(msg->ctlCode);
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;

                    case Smb2Commands::SMB2_SET_INFO:
                        {
                            const std::shared_ptr<SetInfoRequest> msg = std::static_pointer_cast<SetInfoRequest>(message);
                            ss << ", " << queryInfoTypeStrings.at(msg->infoType);
                            if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILE)
                                ss << "/" << fileInfoClassStrings.at(msg->fileInfoClass);
                            else if (msg->infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM)
                                ss << "/" << fsInfoClassStrings.at(msg->fileInfoClass);
                            if (fileHandles.find(msg->fileId) != fileHandles.end() && !fileHandles.at(msg->fileId).empty())
                                ss << ", File: " << fileHandles.at(msg->fileId);
                        }
                        break;
                }
            }
        }

    } else if (headerType == HeaderType::SMB1_PACKET_HEADER) {
        std::shared_ptr<Smb1Header> packetHeader = std::static_pointer_cast<Smb1Header>(header);
        ss << (isResponse ? "[<] " : "[>] ") << smb1CommandToString(packetHeader->command);

    } else if (headerType == HeaderType::SMB2_TRANSFORM_HEADER) {
        ss << "[<|>] " << "Encrypted SMB3";
    } else {
        ss << "[<|>] " << "Compressed SMB3";
    }
    ss << std::endl;
    return ss.str();
}


std::string const pcapfs::smb::SmbPacket::smb1CommandToString(uint8_t cmdCode) {
    std::string result = smb1CommandStrings.find(cmdCode) != smb1CommandStrings.end() ? smb1CommandStrings.at(cmdCode) : "SMB_UNKNOWN";
    result.append(isResponse ? " Response" : " Request");
    return result;
}


std::string const pcapfs::smb::SmbPacket::smb2CommandToString(uint16_t cmdCode) {
    std::string result = cmdCode <= 0x12 ? smb2CommandStrings.at(cmdCode) : "SMB2_UNKNOWN";
    if (cmdCode == Smb2Commands::SMB2_OPLOCK_BREAK)
        result.append(" Message");
    else
        result.append(isResponse ? " Response" : " Request");
    return result;
}
