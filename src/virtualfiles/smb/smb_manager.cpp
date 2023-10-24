#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext, uint32_t treeId) {
    const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
    std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][smbContext->currentCreateRequestFile];
    if (!serverFilePtr) {
        // server file not present in map -> create new one
        serverFilePtr = std::make_shared<SmbServerFile>();
        serverFilePtr->initializeFilePtr(smbContext, smbContext->currentCreateRequestFile, createResponse->lastAccessTime,
                                        createResponse->filesize, treeId);
    } else {
        // server file is already known; update metadata if the current timestamp is newer
        const TimePoint lastAccessTime = winFiletimeToTimePoint(createResponse->lastAccessTime);
        if (lastAccessTime > serverFilePtr->getTimestamp()) {
            serverFilePtr->setTimestamp(lastAccessTime);
            serverFilePtr->setFilesizeRaw(createResponse->filesize);
            serverFilePtr->setFilesizeProcessed(createResponse->filesize);
        }
    }

    serverFiles[endpoint][smbContext->currentCreateRequestFile] = serverFilePtr;
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext, uint32_t treeId) {
    if (smbContext->currentQueryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE &&
        (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION ||
        smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_BASIC_INFORMATION ||
        smbContext-> currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_NETWORK_OPEN_INFORMATION)) {

        const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
        std::string filename = "";
        if (smbContext->fileHandles.find(smbContext->currentQueryInfoRequestData->fileId) != smbContext->fileHandles.end()) {
            // filename already present in fileHandles-map of smbContext
            filename = smbContext->fileHandles.at(smbContext->currentQueryInfoRequestData->fileId);

            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION) {
                const std::string guidAsFilename = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
                if (filename == guidAsFilename) {
                    // filename is only  GUID-string, the real filename can now be extracted from FILE_ALL_INFORMATION
                    filename = queryInfoResponse->filename;
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
                filename = queryInfoResponse->filename;
                // update smbContext so that the mapping between GUID and real filename is now known
                smbContext->fileHandles[smbContext->currentQueryInfoRequestData->fileId] = queryInfoResponse->filename;
            } else {
                filename = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
            }
        }

        std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][filename];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filename, queryInfoResponse->lastAccessTime,
                                            queryInfoResponse->filesize, treeId);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(queryInfoResponse->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getTimestamp()) {
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(queryInfoResponse->filesize);
                serverFilePtr->setFilesizeProcessed(queryInfoResponse->filesize);
            }
        }

        serverFiles[endpoint][filename] = serverFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, SmbContextPtr &smbContext, uint32_t treeId) {
    // update server files with file infos obtained by query directory messages

    bool directoryNameKnown = (smbContext->fileHandles.find(smbContext->currentQueryDirectoryRequestData->fileId) != smbContext->fileHandles.end());
    for (const std::shared_ptr<FileInformation> &fileInfo : fileInfos) {
        std::string filename = "";
        if (directoryNameKnown)
            filename = smbContext->fileHandles.at(smbContext->currentQueryDirectoryRequestData->fileId) + "\\" + fileInfo->filename;
        else
            filename = fileInfo->filename;

        const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
        std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][filename];
        if (!serverFilePtr) {
            // server file not present in map -> create new one
            serverFilePtr = std::make_shared<SmbServerFile>();
            serverFilePtr->initializeFilePtr(smbContext, filename, fileInfo->lastAccessTime,
                                            fileInfo->filesize, treeId);
        } else {
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(fileInfo->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getTimestamp()) {
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(fileInfo->filesize);
                serverFilePtr->setFilesizeProcessed(fileInfo->filesize);
            }
        }

        serverFiles[endpoint][filename] = serverFilePtr;
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


std::vector<pcapfs::FilePtr> const pcapfs::smb::SmbManager::getServerFiles() {
    std::vector<FilePtr> resultVector;
    for (const auto &entry : serverFiles) {
        for (const auto& f : entry.second) {
            resultVector.push_back(f.second);
        }
    }

    return resultVector;
}
