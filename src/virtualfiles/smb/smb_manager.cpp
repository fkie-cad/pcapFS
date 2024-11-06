#include "smb_manager.h"
#include "smb_packet.h"
#include "../smb.h"

#include <numeric>


void pcapfs::smb::SmbManager::parsePacketMinimally(const uint8_t* data, size_t len, uint16_t commandToParse, SmbContextPtr &smbContext) {
    if (*(uint32_t*) data == ProtocolId::SMB2_PACKET_HEADER_ID) {
        // classic SMB2 packet header
        if (len < 64)
            return;

        const std::shared_ptr<Smb2Header> packetHeader = std::make_shared<Smb2Header>(data);
        if (packetHeader->command != commandToParse)
            return ;

        if (!(packetHeader->flags & Smb2HeaderFlags::SMB2_FLAGS_ASYNC_COMMAND)) {
            // TODO: could this lead to errors/bugs?
            smbContext->currentTreeId = packetHeader->treeId;
        }

        smbContext->serverEndpoint.sessionId = packetHeader->sessionId;
        bool isResponse = packetHeader->flags & Smb2HeaderFlags::SMB2_FLAGS_SERVER_TO_REDIR;
        try {
            switch (commandToParse) {
                case Smb2Commands::SMB2_TREE_CONNECT:
                    if (isResponse) {
                        if (packetHeader->status == StatusCodes::STATUS_SUCCESS) {
                            if (smbContext->requestedTrees.find(packetHeader->messageId) == smbContext->requestedTrees.end() ||
                                smbContext->requestedTrees.at(packetHeader->messageId).empty()) {
                                treeNames[smbContext->serverEndpoint][packetHeader->treeId] = "treeId_" + std::to_string(packetHeader->treeId);
                                LOG_TRACE << "add treeid - treename mapping: " << packetHeader->treeId << " - " << treeNames[smbContext->serverEndpoint][packetHeader->treeId];
                            } else {
                                const std::string sanitizedFilename = sanitizeFilename(smbContext->requestedTrees.at(packetHeader->messageId));
                                if (!sanitizedFilename.empty()) {
                                    treeNames[smbContext->serverEndpoint][packetHeader->treeId] = sanitizedFilename;
                                    LOG_TRACE << "add treeid - treename mapping: " << packetHeader->treeId << " - " << sanitizedFilename;
                                }
                            }
                            if (treeNames[smbContext->serverEndpoint].count(packetHeader->treeId)) {
                                const std::string treeName = treeNames[smbContext->serverEndpoint][packetHeader->treeId];
                                LOG_TRACE << "Add " << treeName << " as SMB file";
                                getAsParentDirFile(treeName, smbContext);
                            }
                            smbContext->requestedTrees.erase(packetHeader->messageId);
                        }
                    } else {
                        const std::shared_ptr<TreeConnectRequest> treeConnectRequest =
                            std::make_shared<TreeConnectRequest>(&data[64], len - 64, Version::SMB_VERSION_UNKNOWN);
                        smbContext->requestedTrees[packetHeader->messageId] = treeConnectRequest->pathName;
                    }
                    break;

                case Smb2Commands::SMB2_CREATE:
                    if (isResponse) {
                        const std::shared_ptr<CreateResponse> createResponse = std::make_shared<CreateResponse>(&data[64], len - 64);
                        if (smbContext->createRequestFileNames.find(packetHeader->messageId) != smbContext->createRequestFileNames.end() &&
                            !smbContext->createRequestFileNames.at(packetHeader->messageId).empty()) {
                            const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
                            const std::string filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" +
                                                            smbContext->createRequestFileNames.at(packetHeader->messageId);
                            // update fileId-filename mapping
                            fileHandles[endpointTree][createResponse->fileId] = filePath;

                            SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];
                            if (!smbFilePtr) {
                                // create empty SMB file
                                // SMB files are already created here because otherwise, in certain scenarios with simultaneous SMB share accesses
                                // in different connections, some SMB file (versions) might not be determined
                                LOG_TRACE << "file " << filePath << " is added to the server files";
                                smbFilePtr = std::make_shared<SmbFile>();
                                smbFilePtr->initializeFilePtr(smbContext, filePath, createResponse->metaData);
                                serverFiles[endpointTree][filePath] = smbFilePtr;
                            } else {
                                smbFilePtr->addClientIP(smbContext->clientIP);
                                smbFilePtr->addTimestampToList(smbContext->currentTimestamp, createResponse->metaData);
                            }
                        }
                    } else {
                        const std::shared_ptr<CreateRequest> createRequest = std::make_shared<CreateRequest>(&data[64], len - 64);
                        LOG_TRACE << "create request file: " << createRequest->filename;
                        smbContext->createRequestFileNames[packetHeader->messageId] = createRequest->filename;
                    }
                    break;

                default:
                    return;
            }
        } catch (const SmbError &err) {
            return;
        }
    }
}


void pcapfs::smb::SmbManager::parseSmbConnectionMinimally(const FilePtr &tcpFile, const Bytes &data,
                                                            size_t offsetAfterNbssSetup, uint16_t commandToParse) {
    bool hasNbssSessionSetup = (offsetAfterNbssSetup != 0);
    bool reachedOffsetAfterNbssSetup = false;
    smb::SmbContextPtr smbContext = std::make_shared<smb::SmbContext>(tcpFile, false);
    size_t size = 0;
    const size_t numElements = tcpFile->connectionBreaks.size();
    if (numElements > 0 && commandToParse == Smb2Commands::SMB2_CREATE) {
        const TimePoint oldest = tcpFile->connectionBreaks.at(0).second;
        if (oldest < oldestNetworkTimestamp)
            oldestNetworkTimestamp = oldest;
        const TimePoint newest = tcpFile->connectionBreaks.at(numElements - 1).second;
        if (newest > newestNetworkTimestamp)
            newestNetworkTimestamp = newest;
    }

    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = tcpFile->connectionBreaks.at(i).first;

        if (hasNbssSessionSetup && !reachedOffsetAfterNbssSetup) {
            if (offset == offsetAfterNbssSetup)
                reachedOffsetAfterNbssSetup = true;
            else
                continue;
        }

        if (i == numElements - 1) {
        	size = tcpFile->getFilesizeProcessed() - offset;
        } else {
            size = tcpFile->connectionBreaks.at(i + 1).first - offset;
        }

        // We have a 4 byte NBSS header indicating the NBSS message type
        // and the size of the following SMB data
        if (data.at(offset) != 0) {
            // message type has to be zero
            continue;
        }

        smbContext->currentTimestamp = tcpFile->connectionBreaks.at(i).second;

        size_t smbDataSize = be32toh(*(uint32_t*) &data.at(offset));
        size_t currPos = 0;
        while (smbDataSize != 0 && smbDataSize <= (size - currPos)) {
            // skip NBSS header
            offset += 4;
            currPos += 4;

            parsePacketMinimally(data.data() + offset, smbDataSize, commandToParse, smbContext);
            offset += smbDataSize;
            currPos += smbDataSize;

            // fully parsed this connection break
            if (offset >= data.size())
                break;

            // get size of next SMB2 data
            smbDataSize = be32toh(*(uint32_t*) &data.at(offset));
        }
    }
}


void pcapfs::smb::SmbManager::extractMappings(const std::vector<FilePtr> &tcpFiles, const Index &idx, bool checkNonDefaultPorts) {
    LOG_TRACE << "begin with extracting smb mappings";

    std::vector<std::pair<FilePtr, size_t>> tcpFilesWithSmb;

    for (const auto& tcpFile : tcpFiles) {
        tcpFile->fillBuffer(idx);
        const Bytes data = tcpFile->getBuffer();

        size_t offsetAfterNbssSetup = 0;
        if (!smb::isSmbOverTcp(tcpFile, data, checkNonDefaultPorts)) {
            offsetAfterNbssSetup = smb::getSmbOffsetAfterNbssSetup(tcpFile, data, checkNonDefaultPorts);
            if (offsetAfterNbssSetup == (size_t)-1)
                continue;
        }

        tcpFilesWithSmb.push_back(std::make_pair(tcpFile, offsetAfterNbssSetup));

        parseSmbConnectionMinimally(tcpFile, data, offsetAfterNbssSetup, Smb2Commands::SMB2_TREE_CONNECT);
    }

    for (const auto& tcpFileWithSmb: tcpFilesWithSmb) {
        parseSmbConnectionMinimally(tcpFileWithSmb.first, tcpFileWithSmb.first->getBuffer(),
                                    tcpFileWithSmb.second, Smb2Commands::SMB2_CREATE);
    }
}


pcapfs::smb::ServerEndpointTree const pcapfs::smb::SmbManager::getServerEndpointTree(const SmbContextPtr &smbContext) {
    if (treeNames[smbContext->serverEndpoint].count(smbContext->currentTreeId) == 0) {
        treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] = "treeId_" + std::to_string(smbContext->currentTreeId);
    }
    return ServerEndpointTree(smbContext->serverEndpoint, treeNames[smbContext->serverEndpoint][smbContext->currentTreeId]);
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from query info messages
    LOG_TRACE << "updating SMB server files with query info response infos";

    const std::shared_ptr<QueryInfoRequestData> currentQueryInfoRequestData = smbContext->queryInfoRequestData.at(messageId);

    if (currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
        std::string filePath = "";
        if (fileHandles[endpointTree].find(currentQueryInfoRequestData->fileId) != fileHandles[endpointTree].end()) {
            // filePath already present in fileHandles-map of smbContext
            filePath = fileHandles[endpointTree].at(currentQueryInfoRequestData->fileId);
        } else {
            // filePath not present in fileHandles-map of smbContext
            if (currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION && queryInfoResponse->filename != "") {
                // filename can be determined when we have FILE_ALL_INFORMATION
                filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" + queryInfoResponse->filename;
                // update fileId-filename mapping
                fileHandles[endpointTree][currentQueryInfoRequestData->fileId] = filePath;

            } else if (!smbContext->createRequestFileNames.empty() &&  !smbContext->createRequestFileNames.rbegin()->second.empty() &&
                    currentQueryInfoRequestData->fileId == CHAINED_FILEID) {
                // this case can occur when we have a create request and query info request for the same file are chained together
                // (then, the fileId gets known "too late" for us)
                // => take latest createRequestFileName as file
                // it is ensured that currentCreateRequestFile is a directory
                filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second;
            } else if (queryInfoResponse->filename.empty() && queryInfoResponse->metaData->isDirectory) {
                // probably root directory of the tree
                // can be wrong
                filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId];
            } else {
                // filePath for fileId can't be derived
                return;
            }
        }

        if (!smbContext->createServerFiles)
            return;

        SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];
        if (!smbFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            smbFilePtr = std::make_shared<SmbFile>();
            smbFilePtr->initializeFilePtr(smbContext, filePath, queryInfoResponse->metaData);
        } else {
            smbFilePtr->addTimestampToList(smbContext->currentTimestamp, queryInfoResponse->metaData);
            smbFilePtr->addClientIP(smbContext->clientIP);
        }

        serverFiles[endpointTree][filePath] = smbFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from query directory messages
    LOG_TRACE << "updating SMB server files with query directory response infos";

    const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
    const std::shared_ptr<QueryDirectoryRequestData> currentQueryDirectoryRequestData = smbContext->queryDirectoryRequestData.at(messageId);
    bool directoryNameKnown = (fileHandles[endpointTree].find(currentQueryDirectoryRequestData->fileId) != fileHandles[endpointTree].end());

    for (const std::shared_ptr<FileInformation> &fileInfo : fileInfos) {
        std::string filePath = "";
        if (fileInfo->filename == "." || fileInfo->filename == "..") {
            if (directoryNameKnown)
                filePath = fileHandles[endpointTree].at(currentQueryDirectoryRequestData->fileId);
            else if (!smbContext->createRequestFileNames.empty() &&  !smbContext->createRequestFileNames.rbegin()->second.empty() &&
                    currentQueryDirectoryRequestData->fileId == CHAINED_FILEID) {
                // this case can occur when we have a create request and query directory request for the same file are chained together
                // (then, the fileId gets known "too late" for us)
                // => take latest createRequestFileName
                filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second;
            } else {
                // real file path of "." or ".." could not be determined
                continue;
            }

            if (fileInfo->filename == ".." && serverFiles.count(endpointTree) && serverFiles[endpointTree].count(filePath) &&
                serverFiles[endpointTree][filePath]) {
                // analyze FileInfo of parent directory only when the parent directory is already known as SmbFile
                const SmbFilePtr tmpServerFilePtr = serverFiles[endpointTree][filePath];
                if (tmpServerFilePtr->getParentDir()) {
                    const size_t backslashPos = filePath.rfind("\\");
                    if (backslashPos != std::string::npos) {
                        filePath = std::string(filePath.begin(), filePath.begin()+backslashPos);
                    } else
                        continue;
                } else {
                    // real file path of ".." is beyond root
                    continue;
                }
            } else {
                // real file path of ".." could not be determined
                continue;
            }
        }
        else if (directoryNameKnown)
            filePath = fileHandles[endpointTree].at(currentQueryDirectoryRequestData->fileId) + "\\" + fileInfo->filename;
        else if (!smbContext->createRequestFileNames.empty() && !smbContext->createRequestFileNames.rbegin()->second.empty() &&
                    currentQueryDirectoryRequestData->fileId == CHAINED_FILEID) {
            // this case can occur when we have a create request and query directory request for the same file are chained together
            // (then, the fileId gets known "too late" for us)
            // => take latest createRequestFileName as parent directory
            // it is ensured that currentCreateRequestFile is a directory
            filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second +
                        "\\" + fileInfo->filename;
        } else if (!smbContext->createRequestFileNames.empty() && smbContext->createRequestFileNames.rbegin()->second.empty()) {
            // probably root directory of the tree
            // this could produce wrong result
            filePath = treeNames[smbContext->serverEndpoint][smbContext->currentTreeId] + "\\" + fileInfo->filename;
        } else {
            // filePath for fileId can't be derived
            continue;
        }

        SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];
        if (!smbFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            smbFilePtr = std::make_shared<SmbFile>();
            smbFilePtr->initializeFilePtr(smbContext, filePath, fileInfo->metaData);
        } else {
            smbFilePtr->addTimestampToList(smbContext->currentTimestamp, fileInfo->metaData);
            smbFilePtr->addClientIP(smbContext->clientIP);
        }

        serverFiles[endpointTree][filePath] = smbFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<ReadResponse> &readResponse, const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from read messages

    const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
    const std::shared_ptr<ReadRequestData> currentReadRequestData = smbContext->readRequestData.at(messageId);
    if (fileHandles[endpointTree].find(currentReadRequestData->fileId) == fileHandles[endpointTree].end()) {
        // fileId - filename mapping not known
        return;
    }

    const std::string filePath = fileHandles[endpointTree].at(currentReadRequestData->fileId);
    if (serverFiles[endpointTree].find(filePath) == serverFiles[endpointTree].end() || !serverFiles[endpointTree].at(filePath)) {
        // should not happen
        return;
    }

    LOG_TRACE << "updating SMB server files with read message infos";
    LOG_TRACE << "file to update: " << filePath;

    Fragment newFragment;
    newFragment.id = smbContext->offsetFile->getIdInIndex();
    newFragment.start = smbContext->currentOffset + readResponse->dataOffset;
    // take size of data that is actually read at the end
    newFragment.length = readResponse->dataLength;

    SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];

    if (smbFilePtr->getFilesizeRaw() == 0 && currentReadRequestData->readOffset == 0) {
        // no fragments with file content are saved yet and we have readOffset 0
        LOG_TRACE << "no fragments are saved yet, readOffset == 0";

        smbFilePtr->fragments.push_back(newFragment);
        smbFilePtr->setFilesizeRaw(newFragment.length);
        smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
        smbFilePtr->flags.reset(flags::IS_METADATA);

        smbFilePtr->clearAndAddClientIP(smbContext->clientIP);

        // save timstamps for current version
        smbFilePtr->saveCurrentTimestamps(smbContext->currentTimestamp, smbContext->timeSkew, false);

        smbFilePtr->isCurrentlyReadOperation = true;

        serverFiles[endpointTree][filePath] = smbFilePtr;

    } else if (smbFilePtr->getFilesizeRaw() != 0) {
        // we have already some saved fragments for that file
        // (we only allow following adjacent fragments or fragments at the beginning of the file)

        if (currentReadRequestData->readOffset == smbFilePtr->getFilesizeRaw()) {
            // append fragment to file
            LOG_TRACE << "some fragments are already saved, append new fragment";

            smbFilePtr->fragments.push_back(newFragment);
            smbFilePtr->setFilesizeRaw(currentReadRequestData->readOffset + newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);

            smbFilePtr->isCurrentlyReadOperation = true;

            serverFiles[endpointTree][filePath] = smbFilePtr;

        } else if (currentReadRequestData->readOffset == 0) {
            // create new file version (backup old file version)
            LOG_TRACE << "create new file version";
            smbFilePtr->addAsNewFileVersion();

            // add new Fragment for current file
            smbFilePtr->fragments.clear();
            smbFilePtr->fragments.push_back(newFragment);

            smbFilePtr->saveCurrentTimestamps(smbContext->currentTimestamp, smbContext->timeSkew, false);
            smbFilePtr->clearAndAddClientIP(smbContext->clientIP);
            smbFilePtr->setFilesizeRaw(newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);

            smbFilePtr->isCurrentlyReadOperation = true;

            serverFiles[endpointTree][filePath] = smbFilePtr;
        }
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<WriteRequestData> &writeRequestData, const SmbContextPtr &smbContext) {
    // update server files with file infos obtained from write messages

    const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
    if (fileHandles[endpointTree].find(writeRequestData->fileId) == fileHandles[endpointTree].end()) {
        // fileId - filename mapping not known
        return;
    }

    const std::string filePath = fileHandles[endpointTree].at(writeRequestData->fileId);
    if (serverFiles[endpointTree].find(filePath) == serverFiles[endpointTree].end() || !serverFiles[endpointTree].at(filePath)) {
        // should not happen
        return;
    }

    LOG_TRACE << "updating SMB server files with write message infos";
    LOG_TRACE << "file to update: " << filePath;

    Fragment newFragment;
    newFragment.id = smbContext->offsetFile->getIdInIndex();
    newFragment.start = writeRequestData->globalOffset + writeRequestData->dataOffset;
    newFragment.length = writeRequestData->writeLength;

    SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];

    if (smbFilePtr->getFilesizeRaw() == 0 && writeRequestData->writeOffset == 0) {
        // no fragments with file content are saved yet and we have writeOffset 0
        LOG_TRACE << "no fragments are saved yet, writeOffset == 0";
        smbFilePtr->fragments.push_back(newFragment);
        smbFilePtr->setFilesizeRaw(newFragment.length);
        smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
        smbFilePtr->flags.reset(flags::IS_METADATA);

        smbFilePtr->clearAndAddClientIP(smbContext->clientIP);

        // save timstamps for current version
        smbFilePtr->saveCurrentTimestamps(smbContext->currentTimestamp, smbContext->timeSkew, false);

        smbFilePtr->isCurrentlyReadOperation = false;

        serverFiles[endpointTree][filePath] = smbFilePtr;

    } else if (smbFilePtr->getFilesizeRaw() != 0) {
        // we have already some saved fragments for that file
        // (we only allow following adjacent fragments or fragments at the beginning of the file)

        if (writeRequestData->writeOffset == smbFilePtr->getFilesizeRaw()) {
            // append fragment to file
            LOG_TRACE << "some fragments are already saved, append new fragment";
            smbFilePtr->fragments.push_back(newFragment);
            smbFilePtr->setFilesizeRaw(writeRequestData->writeOffset + newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);

            smbFilePtr->isCurrentlyReadOperation = false;

            serverFiles[endpointTree][filePath] = smbFilePtr;

        } else if (writeRequestData->writeOffset == 0) {
            // create new file version (backup old file version)
            LOG_TRACE << "create new file version";
            smbFilePtr->addAsNewFileVersion();

            // add new Fragment for current file
            smbFilePtr->fragments.clear();
            smbFilePtr->fragments.push_back(newFragment);

            smbFilePtr->saveCurrentTimestamps(smbContext->currentTimestamp, smbContext->timeSkew, false);
            smbFilePtr->clearAndAddClientIP(smbContext->clientIP);
            smbFilePtr->setFilesizeRaw(newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);

            smbFilePtr->isCurrentlyReadOperation = false;

            serverFiles[endpointTree][filePath] = smbFilePtr;
        }
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file metadata obtained from set info message

    const std::shared_ptr<SetInfoRequestData> setInfoRequestData = smbContext->setInfoRequestData[messageId];

    const ServerEndpointTree endpointTree = getServerEndpointTree(smbContext);
    if (fileHandles[endpointTree].find(setInfoRequestData->fileId) == fileHandles[endpointTree].end()) {
        // fileId - filename mapping not known
        return;
    }

    const std::string filePath = fileHandles[endpointTree].at(setInfoRequestData->fileId);
    if (serverFiles[endpointTree].find(filePath) == serverFiles[endpointTree].end() || !serverFiles[endpointTree].at(filePath)) {
        // should not happen
        return;
    }

    LOG_TRACE << "updating SMB server file " << filePath << " with metadata from Set Info Request";

    SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];
    smbFilePtr->addClientIP(smbContext->clientIP);
    smbFilePtr->addTimestampToList(smbContext->currentTimestamp, setInfoRequestData->metaData);
    serverFiles[endpointTree][filePath] = smbFilePtr;
}


void pcapfs::smb::SmbManager::adjustSmbFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, bool noFsTimestamps) {
    std::vector<pcapfs::FilePtr> filesToAdd;
    pcapfs::SmbTimestamps targetTimestamps;
    bool snapshotSpecified = (snapshot != pcapfs::TimePoint::min());
    if (snapshotSpecified) {
        // check if specified snapshot time is in allowed range
        if (noFsTimestamps && (snapshot < oldestNetworkTimestamp || snapshot > newestNetworkTimestamp)) {
            LOG_ERROR << "SMB: Specified snapshot time is not within the capture time interval";
            LOG_ERROR << "Falling back to default mode ...";
            snapshotSpecified = false;
            snapshot = TimePoint::min();
        } else if (!noFsTimestamps) {
            // TODO: neglect this; for filesystem timestamp mode, all snapshot values are allowed!

            // FsTime(oldestNegReponse) - (networkTime(oldestNegReponse) - oldestNetworkTimestamp) + 1
            const TimePoint oldestFsTimestamp = timeOfOldestNegResponse.second - (timeOfOldestNegResponse.first - oldestNetworkTimestamp) + std::chrono::seconds(1);
            const TimePoint newestFsTimestamp = oldestFsTimestamp + (newestNetworkTimestamp - oldestNetworkTimestamp);
            if (snapshot < oldestFsTimestamp || snapshot > newestFsTimestamp) {
                LOG_ERROR << "SMB: Specified snapshot time is not within the capture time interval according to the filesystem time of the SMB share";
                LOG_ERROR << "Falling back to default mode ...";
                snapshotSpecified = false;
                snapshot = TimePoint::min();
            }
        }
    }

    LOG_DEBUG << "preparing smb files for dir layout";

    for (int i = indexFiles.size() - 1; i >= 0; --i) {
        FilePtr currFile = indexFiles.at(i);
        if (currFile->isFiletype("smb")) {
            pcapfs::SmbFilePtr smbFilePtr = std::static_pointer_cast<pcapfs::SmbFile>(indexFiles.at(i));
            if (!smbFilePtr->processFileForDirLayout())
                continue;
            const auto fileVersions = smbFilePtr->getFileVersions();

            if (snapshotSpecified) {

                auto currVersion = fileVersions.begin();
                bool smbTimestampsSet = false;
                if (noFsTimestamps) {
                    // advance to file version corresponding to the specified snapshot time
                    while (currVersion != fileVersions.end() && currVersion->first.networkTime <= snapshot)
                        currVersion++;
                } else {
                    // advance to file version corresponding to the specified snapshot time
                    while (currVersion != fileVersions.end() && currVersion->first.fsTime <= snapshot)
                        currVersion++;

                    // select matching timestamps corresponding to the specified snapshot time
                    for(const auto &entry: smbFilePtr->getTimestampList()) {
                        if ((entry.second.accessTime != ZERO_TIME_POINT && entry.second.accessTime <= snapshot) &&
                            (entry.second.changeTime != ZERO_TIME_POINT && entry.second.changeTime <= snapshot) &&
                            (entry.second.modifyTime != ZERO_TIME_POINT && entry.second.modifyTime <= snapshot)) {
                                targetTimestamps = entry.second;
                                smbTimestampsSet = true;
                        }
                    }
                }

                if (currVersion == fileVersions.begin()) {
                    // at this point, the timestamp for the oldest file version is newer than the requested snapshot time
                    // or no file versions are saved

                    // when we have saved file versions, the file operation corresponding to the oldest file version is READ and we have
                    // a saved timestamp which is older than the snapshot time, then we take the file content from the oldest file version.

                    // otherwise, we can't be sure if the file existed with this version content to that time, so we don't set fragments.
                    // But, when one of the timestamps matches, we take that and make it an empty file.
                    // When we don't have timstamp matched, the file won't be displayed.

                    if (noFsTimestamps) {
                        const auto timestampList = smbFilePtr->getTimestampList();
                        if (currVersion == fileVersions.end()) {
                            // we have an empty metadata file
                            //const auto timestampList = smbFilePtr->getTimestampList();
                            auto entry = timestampList.begin();
                            while (entry != timestampList.end() && entry->first <= snapshot)
                                ++entry;

                            if (entry != timestampList.begin())
                                --entry;

                            if (entry->first > snapshot) {
                                // network timestamp for the oldest file version is newer than the requested snapshot time
                                // -> do not display file
                                indexFiles.erase(indexFiles.begin()+i);
                            } else {
                                smbFilePtr->setAccessTime(entry->first);
                                smbFilePtr->setChangeTime(entry->first);
                                smbFilePtr->setModifyTime(entry->first);
                            }

                        } else {
                            auto timestampPos = timestampList.rbegin();
                            if ((timestampPos = std::find_if(timestampList.rbegin(), timestampList.rend(),
                                    [snapshot](const auto &entry){ return entry.first <= snapshot; }
                                    )) != timestampList.rend()) {
                                smbFilePtr->fragments.clear(),
                                smbFilePtr->setFilesizeRaw(0);
                                smbFilePtr->setFilesizeProcessed(0);
                                smbFilePtr->flags.set(pcapfs::flags::IS_METADATA);
                                LOG_DEBUG << "found no matching file version for " << smbFilePtr->getFilename() << " but a matching timestamp"
                                            << " => create empty metadata file";
                            } else {
                                LOG_DEBUG << "didn't find matching timestamp for " << smbFilePtr->getFilename();
                                indexFiles.erase(indexFiles.begin()+i);
                            }
                        }
                    } else {
                        if (smbTimestampsSet) {
                            if (fileVersions.size() > 0 && targetTimestamps.changeTime <= snapshot && currVersion->second.readOperation) {
                                smbFilePtr->fragments = currVersion->second.fragments;
                                smbFilePtr->setClientIPs(currVersion->second.clientIPs);
                                const size_t calculatedFilesize = std::accumulate(smbFilePtr->fragments.begin(), smbFilePtr->fragments.end(), 0,
                                                                            [](size_t counter, const auto &frag){ return counter + frag.length; });
                                smbFilePtr->setFilesizeRaw(calculatedFilesize);
                                smbFilePtr->setFilesizeProcessed(calculatedFilesize);
                            } else {
                                smbFilePtr->fragments.clear(),
                                smbFilePtr->setFilesizeRaw(0);
                                smbFilePtr->setFilesizeProcessed(0);
                                smbFilePtr->flags.set(pcapfs::flags::IS_METADATA);
                            }
                            smbFilePtr->setAccessTime(targetTimestamps.accessTime);
                            smbFilePtr->setChangeTime(targetTimestamps.changeTime);
                            smbFilePtr->setModifyTime(targetTimestamps.modifyTime);
                            indexFiles[i] = smbFilePtr;
                        } else {
                            indexFiles.erase(indexFiles.begin()+i);
                            LOG_DEBUG << "didn't find matching timestamp for " << smbFilePtr->getFilename();
                        }
                    }
                } else {
                    // found matching file version
                    currVersion--;

                    smbFilePtr->fragments = currVersion->second.fragments;
                    smbFilePtr->setClientIPs(currVersion->second.clientIPs);
                    const size_t calculatedFilesize = std::accumulate(smbFilePtr->fragments.begin(), smbFilePtr->fragments.end(), 0,
                                                                [](size_t counter, const auto &frag){ return counter + frag.length; });
                    smbFilePtr->setFilesizeRaw(calculatedFilesize);
                    smbFilePtr->setFilesizeProcessed(calculatedFilesize);

                    if (noFsTimestamps) {
                        smbFilePtr->setAccessTime(currVersion->first.networkTime);
                        smbFilePtr->setChangeTime(currVersion->first.networkTime);
                        smbFilePtr->setModifyTime(currVersion->first.networkTime);
                    } else {
                        if (smbTimestampsSet) {
                            smbFilePtr->setAccessTime(targetTimestamps.accessTime);
                            smbFilePtr->setChangeTime(targetTimestamps.changeTime);
                            smbFilePtr->setModifyTime(targetTimestamps.modifyTime);
                        } else {
                            // no matching timestamps found
                            smbFilePtr->setAccessTime(ZERO_TIME_POINT);
                            smbFilePtr->setChangeTime(ZERO_TIME_POINT);
                            smbFilePtr->setModifyTime(ZERO_TIME_POINT);
                        }
                    }
                    indexFiles[i] = smbFilePtr;
                }

            } else if (!smbFilePtr->isDirectory) {
                // no snapshot time specified -> create separate smb file for each version
                std::vector<pcapfs::SmbFilePtr> smbFileVersions = smbFilePtr->constructSmbVersionFiles();
                filesToAdd.insert(filesToAdd.end(), smbFileVersions.begin(), smbFileVersions.end());
                if (smbFileVersions.size() != 0) {
                    // old smb file is not needed anymore since we now have all versions of it as separate files
                    indexFiles.erase(indexFiles.begin()+i);
                }
            } else if (smbFilePtr->isDirectory) {
                smbFilePtr->setNearestTimestamp();
            }
        }
    }

    indexFiles.insert(indexFiles.end(), filesToAdd.begin(), filesToAdd.end());
}


pcapfs::smb::SmbFileHandles const pcapfs::smb::SmbManager::getFileHandles(const SmbContextPtr &smbContext) {
    return fileHandles[getServerEndpointTree(smbContext)];
}


pcapfs::SmbFilePtr const pcapfs::smb::SmbManager::getAsParentDirFile(const std::string &filePath, const SmbContextPtr &smbContext) {
    const ServerEndpointTree endpt = getServerEndpointTree(smbContext);
    if (serverFiles[endpt].find(filePath) != serverFiles[endpt].end()) {
        LOG_DEBUG << "parent directory is already known as an SmbFile";
        serverFiles[endpt][filePath]->addClientIP(smbContext->clientIP);
        return serverFiles[endpt][filePath];
    } else {
        LOG_DEBUG << "parent directory not known as SmbFile yet, create parent dir file on the fly";
        FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
        // initially, all timestamps are set to 0
        metaData->isDirectory = true;
        SmbFilePtr smbFilePtr = std::make_shared<SmbFile>();
        smbFilePtr->initializeFilePtr(smbContext, filePath, metaData);
        serverFiles[endpt][filePath] = smbFilePtr;
        return smbFilePtr;
    }
}


uint64_t pcapfs::smb::SmbManager::getNewId() {
    const uint64_t newId = idCounter;
    idCounter++;
    return newId;
}


std::vector<pcapfs::FilePtr> const pcapfs::smb::SmbManager::getSmbFiles(const Index &idx) {
    std::vector<FilePtr> resultVector;

    LOG_DEBUG << "Collecting all SMB files...";
    for (const auto &endpt : serverFiles) {
        for (auto &fileEntry: endpt.second) {
            fileEntry.second->deduplicateVersions(idx);
            resultVector.push_back(fileEntry.second);
        }
    }

    return resultVector;
}


void pcapfs::smb::SmbManager::setTimeOfNegResponse(const TimePoint &fsTime, const TimePoint &networkTime) {
    if (networkTime < timeOfOldestNegResponse.first) {
        timeOfOldestNegResponse = std::pair<TimePoint, TimePoint>(networkTime, fsTime);
    }
}


void pcapfs::smb::SmbManager::serialize(boost::archive::text_oarchive &archive, const unsigned int&) {
    archive << treeNames;
    archive << fileHandles;
    archive << oldestNetworkTimestamp;
    archive << newestNetworkTimestamp;
    archive << timeOfOldestNegResponse;
}


void pcapfs::smb::SmbManager::deserialize(boost::archive::text_iarchive &archive, const unsigned int&) {
    archive >> treeNames;
    archive >> fileHandles;
    archive >> oldestNetworkTimestamp;
    archive >> newestNetworkTimestamp;
    archive >> timeOfOldestNegResponse;
}
