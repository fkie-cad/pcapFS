#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from create messages
    LOG_TRACE << "updating SMB server files with create response infos";

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
    const std::string filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.at(messageId);

    // update fileId-filename mapping
    fileHandles[endpointTree][createResponse->fileId] = filePath;

    if (!createResponse->metaData->isDirectory) {
        // this prevents possible wrong file path compositions in the other updateServerFiles functions in the case that
        // currentCreateRequestFile is chosen as parent directory path of the respective server files although
        // it isn't even a directory
        smbContext->createRequestFileNames.at(messageId) = "";
    }

    if (!smbContext->createServerFiles)
        return;

    SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
    if (!serverFilePtr) {
        // server file not present in map -> create new one
        LOG_TRACE << "file " << filePath << " is new and added to the server files";
        serverFilePtr = std::make_shared<SmbServerFile>();
        serverFilePtr->initializeFilePtr(smbContext, filePath, createResponse->metaData);
    } else {
        // server file is already known; update metadata if the current timestamp is newer
        // for NTFS timestamps, changeTime is the most sensitive one
        const TimePoint lastChangeTime = winFiletimeToTimePoint(createResponse->metaData->changeTime);
        if (lastChangeTime > serverFilePtr->getChangeTime()) {
            LOG_TRACE << "file " << filePath << " is already known and updated";
            serverFilePtr->setTimestamp(lastChangeTime);
            serverFilePtr->setFilesizeRaw(createResponse->metaData->filesize);
            serverFilePtr->setFilesizeProcessed(createResponse->metaData->filesize);
            serverFilePtr->setAccessTime(smb::winFiletimeToTimePoint(createResponse->metaData->lastAccessTime));
            serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(createResponse->metaData->lastWriteTime));
            serverFilePtr->setChangeTime(lastChangeTime);
        }
    }

    serverFiles[endpointTree][filePath] = serverFilePtr;
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from query info messages
    LOG_TRACE << "updating SMB server files with query info response infos";

    const std::shared_ptr<QueryInfoRequestData> currentQueryInfoRequestData = smbContext->queryInfoRequestData.at(messageId);

    if (currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
        std::string filePath = "";
        if (fileHandles[endpointTree].find(currentQueryInfoRequestData->fileId) != fileHandles[endpointTree].end()) {
            // filePath already present in fileHandles-map of smbContext
            filePath = fileHandles[endpointTree].at(currentQueryInfoRequestData->fileId);
        } else {
            // filePath not present in fileHandles-map of smbContext
            if (currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION && queryInfoResponse->filename != "") {
                // filename can be determined when we have FILE_ALL_INFORMATION
                filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + queryInfoResponse->filename;

            } else if (!smbContext->createRequestFileNames.empty() &&  !smbContext->createRequestFileNames.rbegin()->second.empty() &&
                    currentQueryInfoRequestData->fileId == CHAINED_FILEID) {
                // this case can occur when we have a create request and query info request for the same file are chained together
                // (then, the fileId gets known "too late" for us)
                // => take latest createRequestFileName as file
                // it is ensured that currentCreateRequestFile is a directory
                filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second;
            } else if (queryInfoResponse->filename.empty() && queryInfoResponse->metaData->isDirectory) {
                // probably root directory of the tree
                // can be wrong
                filePath = smbContext->treeNames[smbContext->currentTreeId];
            } else {
                // filePath for fileId can't be derived
                return;
            }

            // update fileId-filename mapping
            fileHandles[endpointTree][currentQueryInfoRequestData->fileId] = filePath;

        }

        if (!smbContext->createServerFiles)
            return;

        SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, queryInfoResponse->metaData);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastChangeTime = winFiletimeToTimePoint(queryInfoResponse->metaData->changeTime);
            if (lastChangeTime > serverFilePtr->getChangeTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastChangeTime);
                serverFilePtr->setFilesizeRaw(queryInfoResponse->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(queryInfoResponse->metaData->filesize);
                serverFilePtr->setAccessTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->lastAccessTime));
                serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->lastWriteTime));
                serverFilePtr->setChangeTime(lastChangeTime);
            }
        }

        serverFiles[endpointTree][filePath] = serverFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from query directory messages
    LOG_TRACE << "updating SMB server files with query directory response infos";

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
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
                filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second;
            } else {
                // real file path of "." or ".." could not be determined
                continue;
            }

            if (fileInfo->filename == ".." && serverFiles.count(endpointTree) && serverFiles[endpointTree].count(filePath) &&
                serverFiles[endpointTree][filePath]) {
                // analyze FileInfo of parent directory only when the parent directory is already known as SmbServerFile
                const SmbServerFilePtr tmpServerFilePtr = serverFiles[endpointTree][filePath];
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
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second + "\\" + fileInfo->filename;
        } else if (!smbContext->createRequestFileNames.empty() && smbContext->createRequestFileNames.rbegin()->second.empty()) {
            // probably root directory of the tree
            // this could produce wrong result
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + fileInfo->filename;
        } else {
            // filePath for fileId can't be derived
            continue;
        }

        SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, fileInfo->metaData);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastChangeTime = winFiletimeToTimePoint(fileInfo->metaData->changeTime);
            if (lastChangeTime > serverFilePtr->getChangeTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastChangeTime);
                serverFilePtr->setFilesizeRaw(fileInfo->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(fileInfo->metaData->filesize);
                serverFilePtr->setAccessTime(smb::winFiletimeToTimePoint(fileInfo->metaData->lastAccessTime));
                serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(fileInfo->metaData->lastWriteTime));
                serverFilePtr->setChangeTime(lastChangeTime);
            }
        }

        serverFiles[endpointTree][filePath] = serverFilePtr;
    }
}


pcapfs::smb::SmbFileHandles const pcapfs::smb::SmbManager::getFileHandles(const SmbContextPtr &smbContext) {
    return fileHandles[smbContext->getServerEndpointTree()];
}


pcapfs::SmbServerFilePtr const pcapfs::smb::SmbManager::getAsParentDirFile(const std::string &filePath, SmbContextPtr &smbContext) {
    const ServerEndpointTree endpt = smbContext->getServerEndpointTree();
    if (serverFiles[endpt].find(filePath) != serverFiles[endpt].end()) {
        LOG_TRACE << "parent directory is already known as an SmbFile";
        return serverFiles[endpt][filePath];
    } else {
        LOG_TRACE << "parent directory not known as SmbServerFile yet, create parent dir file on the fly";
        FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
        // initially, all timestamps are set to 0
        metaData->isDirectory = true;
        SmbServerFilePtr serverFilePtr = std::make_shared<SmbServerFile>();
        serverFilePtr->initializeFilePtr(smbContext, filePath, metaData);
        serverFiles[endpt][filePath] = serverFilePtr;
        return serverFilePtr;
    }
}


uint64_t pcapfs::smb::SmbManager::getNewId() {
    const uint64_t newId = idCounter;
    idCounter++;
    return newId;
}


std::vector<pcapfs::FilePtr> const pcapfs::smb::SmbManager::getServerFiles() {
    std::vector<FilePtr> resultVector;
    for (const auto &entry : serverFiles) {
        for (const auto &f : entry.second) {
            // TODO: neglect this while loop?
            ServerFilePtr serverFile = f.second;
            while (serverFile->getParentDir()) {
                serverFile = std::static_pointer_cast<ServerFile>(serverFile->getParentDir());
            }
            resultVector.push_back(f.second);
        }
    }
    return resultVector;
}
