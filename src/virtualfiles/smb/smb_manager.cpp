#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext, uint32_t treeId) {
    // update server files with file infos obtained from create messages
    LOG_TRACE << "updating SMB server files with create response infos";

    const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
    SmbServerFilePtr serverFilePtr = serverFiles[endpoint][smbContext->currentCreateRequestFile];
    if (!serverFilePtr) {
        // server file not present in map -> create new one
        LOG_TRACE << "file " << smbContext->currentCreateRequestFile << " is new and added to the server files";
        serverFilePtr = std::make_shared<SmbServerFile>();
        serverFilePtr->initializeFilePtr(smbContext, smbContext->currentCreateRequestFile, createResponse->metaData, endpoint, treeId);
    } else {
        // server file is already known; update metadata if the current timestamp is newer

        // TODO: consider all timestamps
        const TimePoint lastAccessTime = winFiletimeToTimePoint(createResponse->metaData->lastAccessTime);
        if (lastAccessTime > serverFilePtr->getAccessTime()) {
            LOG_TRACE << "file " << smbContext->currentCreateRequestFile << " is already known and updated";
            serverFilePtr->setTimestamp(lastAccessTime);
            serverFilePtr->setFilesizeRaw(createResponse->metaData->filesize);
            serverFilePtr->setFilesizeProcessed(createResponse->metaData->filesize);
        }
    }

    serverFiles[endpoint][smbContext->currentCreateRequestFile] = serverFilePtr;
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext, uint32_t treeId) {
    // update server files with file infos obtained from query info messages
    LOG_TRACE << "updating SMB server files with query info response infos";

    if (smbContext->currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        smbContext-> currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
        std::string filePath = "";
        if (smbContext->fileHandles.find(smbContext->currentQueryInfoRequestData->fileId) != smbContext->fileHandles.end()) {
            // filePath already present in fileHandles-map of smbContext
            filePath = smbContext->fileHandles.at(smbContext->currentQueryInfoRequestData->fileId);

            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION) {

                // TODO: maybe in further development, I won't use GUID-string filenames anymore, then this might become obsolete
                const std::string guidAsFilename = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
                if (filePath == guidAsFilename) {
                    // filename is only  GUID-string, the real filename can now be extracted from FILE_ALL_INFORMATION
                    if (smbContext->currentCreateRequestFile != "")
                        filePath = smbContext->currentCreateRequestFile + "\\" + queryInfoResponse->filename;
                    else
                        filePath = queryInfoResponse->filename;
                    // update smbContext so that the mapping between GUID and real filename is now known
                    smbContext->fileHandles[smbContext->currentQueryInfoRequestData->fileId] = queryInfoResponse->filename;

                    if (serverFiles[endpoint].find(guidAsFilename) != serverFiles[endpoint].end()) {
                        // in the serverFiles-map of the SMB manager, the name of the file whose FILE_ALL_INFORMATION is returned is
                        // already known as its GUID-string (which is set when the real file name is unknown)
                        // but, since now through FILE_ALL_INFORMATION the real file name is known, we delete the file entry,
                        // which is indexed by the GUID-string, so that we do not have two versions of the same file at the end
                        // (one with GUID-string as file name and the other one with the real file name)
                        serverFiles[endpoint].erase(guidAsFilename);
                    }
                }
            }
        } else {
            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION) {
                // filename is only  GUID-string, the real filename can now be extracted from FILE_ALL_INFORMATION
                if (smbContext->currentCreateRequestFile != "")
                    filePath = smbContext->currentCreateRequestFile + "\\" + queryInfoResponse->filename;
                else
                    filePath = queryInfoResponse->filename;
                // update smbContext so that the mapping between GUID and real filename is now known
                smbContext->fileHandles[smbContext->currentQueryInfoRequestData->fileId] = queryInfoResponse->filename;
            } else {
                // TODO: maybe in further development, I won't use GUID-string filenames anymore, then this might become obsolete
                // and we would return here
                filePath = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
            }
        }

        SmbServerFilePtr serverFilePtr = serverFiles[endpoint][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, queryInfoResponse->metaData, endpoint, treeId);
        } else {
            // server file is already known; update metadata if the current timestamp is newer

            // TODO: consider all timestamps
            const TimePoint lastAccessTime = winFiletimeToTimePoint(queryInfoResponse->metaData->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(queryInfoResponse->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(queryInfoResponse->metaData->filesize);
            }
        }

        serverFiles[endpoint][filePath] = serverFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext, uint32_t treeId) {
    // update server files with file infos obtained from query directory messages
    LOG_TRACE << "updating SMB server files with query directory response infos";

    bool directoryNameKnown = (smbContext->fileHandles.find(smbContext->currentQueryDirectoryRequestData->fileId) != smbContext->fileHandles.end());
    const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);

    for (const std::shared_ptr<FileInformation> &fileInfo : fileInfos) {
        std::string filePath = "";
        if (directoryNameKnown)
            filePath = smbContext->fileHandles.at(smbContext->currentQueryDirectoryRequestData->fileId) + "\\" + fileInfo->filename;
        else if (smbContext->currentCreateRequestFile != "")
            filePath = smbContext->currentCreateRequestFile + "\\" + fileInfo->filename;
        else
            filePath = fileInfo->filename;

        SmbServerFilePtr serverFilePtr = serverFiles[endpoint][filePath];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            LOG_TRACE << "file " << filePath << " is new and added to the server files";
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filePath, fileInfo->metaData, endpoint, treeId);
        } else {
            // server file is already known; update metadata if the current timestamp is newer

            // TODO: consider all timestamps
            const TimePoint lastAccessTime = winFiletimeToTimePoint(fileInfo->metaData->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(fileInfo->metaData->filesize);
                serverFilePtr->setFilesizeProcessed(fileInfo->metaData->filesize);
            }
        }

        serverFiles[endpoint][filePath] = serverFilePtr;
    }
}


pcapfs::smb::ServerEndpoint const pcapfs::smb::SmbManager::getServerEndpoint(const FilePtr &filePtr, uint32_t treeId) {
    ServerEndpoint endpoint;
    const uint16_t srcPort = strToUint16(filePtr->getProperty("srcPort"));
    if (srcPort == 445 || srcPort == 139) {
        endpoint.ipAddress = pcpp::IPAddress(filePtr->getProperty("srcIP"));
        endpoint.port = srcPort;
    } else {
        // take dstIP and dstPort as server endpoint
        // this might be client IP and client port if checkNonDefaultPorts config is set
        // and the server does not use the default port 445 or 139
        endpoint.ipAddress = pcpp::IPAddress(filePtr->getProperty("dstIP"));
        endpoint.port = strToUint16(filePtr->getProperty("dstPort"));
    }
    endpoint.treeId = treeId;
    return endpoint;
}


void pcapfs::smb::SmbManager::createParentDirFile(const std::shared_ptr<smb::SmbContext> &smbContext, const std::string &filePath,
                                                    const smb::ServerEndpoint &endpoint, uint32_t treeId) {
    FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
    // initially, all timestamps are set to 0
    metaData->isDirectory = true;
    SmbServerFilePtr serverFilePtr = std::make_shared<SmbServerFile>();
    serverFilePtr->initializeFilePtr(smbContext, filePath, metaData, endpoint, treeId);
    serverFiles[endpoint][filePath] = serverFilePtr;
}


std::vector<pcapfs::FilePtr> const pcapfs::smb::SmbManager::getServerFiles() {
    LOG_TRACE << "getting all SMB server files...";
    std::vector<FilePtr> resultVector;
    for (const std::pair<ServerEndpoint,SmbServerFiles> &entry : serverFiles) {
        for (const std::pair<std::string,SmbServerFilePtr> &f : entry.second) {
            ServerFilePtr serverFile = f.second;
            LOG_ERROR << "parent dir cascade of " << serverFile->getFilename();
            LOG_ERROR << "(saved with key " << f.first << "):";
            while (serverFile->getParentDir()) {
                LOG_ERROR << serverFile->getParentDir()->getFilename();
                serverFile = serverFile->getParentDir();
            }
            LOG_ERROR << "\n\n";

            resultVector.push_back(f.second);
        }
    }

    return resultVector;
}
