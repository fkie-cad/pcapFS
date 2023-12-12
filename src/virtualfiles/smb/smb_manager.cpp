#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, SmbContextPtr &smbContext) {
    // update server files with file infos obtained from create messages
    LOG_TRACE << "updating SMB server files with create response infos";

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
    const std::string filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->currentCreateRequestFile;

    // update fileId-filename mapping
    fileHandles[endpointTree][createResponse->fileId] = filePath;
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

    if (!createResponse->metaData->isDirectory) {
        // this prevents possible wrong file path compositions in the other updateServerFiles functions in the case that
        // currentCreateRequestFile is chosen as parent directory path of the respective server files although
        // it isn't even a directory
        smbContext->currentCreateRequestFile = "";
    }
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext) {
    // update server files with file infos obtained from query info messages
    LOG_TRACE << "updating SMB server files with query info response infos";

    if (smbContext->currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        smbContext-> currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
        std::string filePath = "";
        if (fileHandles[endpointTree].find(smbContext->currentQueryInfoRequestData->fileId) != fileHandles[endpointTree].end()) {
            // filePath already present in fileHandles-map of smbContext
            filePath = fileHandles[endpointTree].at(smbContext->currentQueryInfoRequestData->fileId);
        } else {
            // filePath not present in fileHandles-map of smbContext
            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION && queryInfoResponse->filename != "") {
                // filename can be determined when we have FILE_ALL_INFORMATION
                filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\";

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


void pcapfs::smb::SmbManager::updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, SmbContextPtr &smbContext) {
    // update server files with file infos obtained from query directory messages
    LOG_TRACE << "updating SMB server files with query directory response infos";

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
    bool directoryNameKnown = (fileHandles[endpointTree].find(smbContext->currentQueryDirectoryRequestData->fileId) != fileHandles[endpointTree].end());

    for (const std::shared_ptr<FileInformation> &fileInfo : fileInfos) {
        std::string filePath = "";
        if (fileInfo->filename == "." || fileInfo->filename == "..") {
            if (directoryNameKnown)
                filePath = fileHandles[endpointTree].at(smbContext->currentQueryDirectoryRequestData->fileId);
            else if (smbContext->currentCreateRequestFile != "") {
                // this could produce wrong result
                filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->currentCreateRequestFile;
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
            filePath = fileHandles[endpointTree].at(smbContext->currentQueryDirectoryRequestData->fileId) + "\\" + fileInfo->filename;
        else if (smbContext->currentCreateRequestFile != "")
            // this could produce wrong result
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" +
                        smbContext->currentCreateRequestFile + "\\" + fileInfo->filename;
        else
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + fileInfo->filename;

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
            ServerFilePtr serverFile = f.second;
            while (serverFile->getParentDir()) {
                serverFile = std::static_pointer_cast<ServerFile>(serverFile->getParentDir());
            }
            resultVector.push_back(f.second);
        }
    }
    return resultVector;
}
