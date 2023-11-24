#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext) {
    // update server files with file infos obtained from create messages
    LOG_TRACE << "updating SMB server files with create response infos";

    const ServerEndpointTree endpointTree(smbContext->serverEndpoint, smbContext->currentTreeId);

    const std::string filePath = constructTreeString(smbContext->serverEndpoint, smbContext->currentTreeId) + "\\" + smbContext->currentCreateRequestFile;

    // update fileId-filename mapping
    fileHandles[endpointTree][createResponse->fileId] = filePath;

    SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
    if (!serverFilePtr) {
        // server file not present in map -> create new one
        LOG_TRACE << "file " << filePath << " is new and added to the server files";
        serverFilePtr = std::make_shared<SmbServerFile>();
        serverFilePtr->initializeFilePtr(smbContext, filePath, createResponse->metaData);
    } else {
        // server file is already known; update metadata if the current timestamp is newer
        const TimePoint lastAccessTime = winFiletimeToTimePoint(createResponse->metaData->lastAccessTime);
        if (lastAccessTime > serverFilePtr->getAccessTime()) {
            LOG_TRACE << "file " << filePath << " is already known and updated";
            serverFilePtr->setTimestamp(lastAccessTime);
            serverFilePtr->setFilesizeRaw(createResponse->metaData->filesize);
            serverFilePtr->setFilesizeProcessed(createResponse->metaData->filesize);
            serverFilePtr->setAccessTime(lastAccessTime);
            serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(createResponse->metaData->lastWriteTime));
            serverFilePtr->setChangeTime(smb::winFiletimeToTimePoint(createResponse->metaData->changeTime));
        }
    }

    serverFiles[endpointTree][filePath] = serverFilePtr;
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext) {
    // update server files with file infos obtained from query info messages
    LOG_TRACE << "updating SMB server files with query info response infos";

    if (smbContext->currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        smbContext-> currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpointTree endpointTree(smbContext->serverEndpoint, smbContext->currentTreeId);
        std::string filePath = "";
        if (fileHandles[endpointTree].find(smbContext->currentQueryInfoRequestData->fileId) != fileHandles[endpointTree].end()) {
            // filePath already present in fileHandles-map of smbContext
            filePath = fileHandles[endpointTree].at(smbContext->currentQueryInfoRequestData->fileId);
        } else {
            // filePath not present in fileHandles-map of smbContext
            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION && queryInfoResponse->filename != "") {
                // filename can be determined when we have FILE_ALL_INFORMATION
                filePath = constructTreeString(smbContext->serverEndpoint, smbContext->currentTreeId) + "\\";

                // this could produce wrong result
                if (smbContext->currentCreateRequestFile != "")
                    filePath += smbContext->currentCreateRequestFile + "\\" + queryInfoResponse->filename;
                else
                    filePath += queryInfoResponse->filename;
                // update smbContext so that the mapping between GUID and filename is now known
                fileHandles[endpointTree][smbContext->currentQueryInfoRequestData->fileId] = filePath;
            } else {
                // we cannot determine the filename to the GUID -> return
                return;
            }
        }

        SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, queryInfoResponse->metaData);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(queryInfoResponse->metaData->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(queryInfoResponse->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(queryInfoResponse->metaData->filesize);
                serverFilePtr->setAccessTime(lastAccessTime);
                serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->lastWriteTime));
                serverFilePtr->setChangeTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->changeTime));
            }
        }

        serverFiles[endpointTree][filePath] = serverFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext) {
    // update server files with file infos obtained from query directory messages
    LOG_TRACE << "updating SMB server files with query directory response infos";

    const ServerEndpointTree endpointTree(smbContext->serverEndpoint, smbContext->currentTreeId);
    bool directoryNameKnown = (fileHandles[endpointTree].find(smbContext->currentQueryDirectoryRequestData->fileId) != fileHandles[endpointTree].end());

    for (const std::shared_ptr<FileInformation> &fileInfo : fileInfos) {
        std::string filePath = "";
        if (directoryNameKnown)
            filePath = fileHandles[endpointTree].at(smbContext->currentQueryDirectoryRequestData->fileId) + "\\" + fileInfo->filename;
        else if (smbContext->currentCreateRequestFile != "")
            // this could produce wrong result
            filePath = constructTreeString(smbContext->serverEndpoint, smbContext->currentTreeId) + "\\" +
                        smbContext->currentCreateRequestFile + "\\" + fileInfo->filename;
        else
            filePath = constructTreeString(smbContext->serverEndpoint, smbContext->currentTreeId) + "\\" + fileInfo->filename;

        SmbServerFilePtr serverFilePtr = serverFiles[endpointTree][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, fileInfo->metaData);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(fileInfo->metaData->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(fileInfo->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(fileInfo->metaData->filesize);
                serverFilePtr->setAccessTime(lastAccessTime);
                serverFilePtr->setModifyTime(smb::winFiletimeToTimePoint(fileInfo->metaData->lastWriteTime));
                serverFilePtr->setChangeTime(smb::winFiletimeToTimePoint(fileInfo->metaData->changeTime));
            }
        }

        serverFiles[endpointTree][filePath] = serverFilePtr;
    }
}


void pcapfs::smb::SmbManager::addTreeNameMapping(const ServerEndpoint &endp, uint32_t treeId, const std::string &treeName) {
    if (treeName.empty() || std::all_of(treeName.begin(), treeName.end(), [](const unsigned char c ){ return c == 0x5C; }))
        return;
    if (treeName.back() == 0x5C) {
        // chop off ending backslash(es)
        const auto it = std::find_if(treeName.rbegin(), treeName.rend(), [](const unsigned char c){ return c != 0x5C; });
        treeNames[endp][treeId] = std::string(treeName.begin(), it.base());
    } else
        treeNames[endp][treeId] = treeName;
}


std::string const pcapfs::smb::SmbManager::constructTreeString(const ServerEndpoint &endp, uint32_t treeId) {
    if (treeNames[endp].find(treeId) != treeNames[endp].end())
        return treeNames[endp][treeId];
    else
        return "treeId_" + std::to_string(treeId);
}


pcapfs::SmbServerFilePtr const pcapfs::smb::SmbManager::getAsParentDirFile(const std::string &filePath, const std::shared_ptr<smb::SmbContext> &smbContext) {
    const ServerEndpointTree endpt(smbContext->serverEndpoint, smbContext->currentTreeId);
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
            ServerFilePtr serverFile = f.second;
            while (serverFile->getParentDir()) {
                serverFile = std::static_pointer_cast<ServerFile>(serverFile->getParentDir());
            }
            resultVector.push_back(f.second);
        }
    }
    return resultVector;
}
