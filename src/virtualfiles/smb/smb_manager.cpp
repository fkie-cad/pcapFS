#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext, uint32_t treeId) {
    const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
    std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][smbContext->currentCreateRequestFile];
    if (!serverFilePtr) {
        serverFilePtr = std::make_shared<SmbServerFile>();

        Fragment fragment;
        fragment.id = smbContext->offsetFile->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        serverFilePtr->fragments.push_back(fragment);
        serverFilePtr->setFilename(smbContext->currentCreateRequestFile);
        serverFilePtr->setTimestamp(winFiletimeToTimePoint(createResponse->lastAccessTime));
        serverFilePtr->setProperty("protocol", "smb");
        serverFilePtr->setFiletype("smbserverfile");
        serverFilePtr->setOffsetType(smbContext->offsetFile->getFiletype());
        serverFilePtr->setProperty("srcIP", smbContext->offsetFile->getProperty("srcIP"));
        serverFilePtr->setProperty("dstIP", smbContext->offsetFile->getProperty("dstIP"));
        serverFilePtr->setProperty("srcPort", smbContext->offsetFile->getProperty("srcPort"));
        serverFilePtr->setProperty("dstPort", smbContext->offsetFile->getProperty("dstPort"));
        if (smbContext->treeNames.find(treeId) != smbContext->treeNames.end())
            serverFilePtr->setProperty("smbTree", smbContext->treeNames.at(treeId));
        serverFilePtr->flags.set(pcapfs::flags::PROCESSED);
        serverFilePtr->setFilesizeRaw(createResponse->filesize);
        serverFilePtr->setFilesizeProcessed(createResponse->filesize);

    } else {
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
            filename = smbContext->fileHandles.at(smbContext->currentQueryInfoRequestData->fileId);

            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION) {
                const std::string guidAsFilename = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
                if (filename == guidAsFilename) {
                    // real filename not known priorly but can be extracted from FILE_ALL_INFORMATION
                    filename = queryInfoResponse->filename;
                    // update smbContext so that the real GUID-filename mapping is now known
                    smbContext->fileHandles[smbContext->currentQueryInfoRequestData->fileId] = queryInfoResponse->filename;

                    if (serverFiles[endpoint].find(guidAsFilename) != serverFiles[endpoint].end()) {
                        // in the serverFiles-map, the name of the file whose FILE_ALL_INFORMATION is returned is already known
                        // as its GUID-string (which is set when the real file name is unknown)
                        // but, since now through FILE_ALL_INFORMATION the real file name is known, we delete the file entry,
                        // which is indexed by the GUID-string, so that we do not have two versions of the same file at the end
                        // (one with GUID-string as file name and the other one with the real file name)
                        serverFiles[endpoint].erase(guidAsFilename);
                    }
                }
            }
        } else {
            if (smbContext->currentQueryInfoRequestData->fileInfoClass == FileInfoClass::FILE_ALL_INFORMATION) {
                // filename not known priorly but can be extracted from FILE_ALL_INFORMATION
                filename = queryInfoResponse->filename;
                // update smbContext so that GUID-filename mapping is now known
                smbContext->fileHandles[smbContext->currentQueryInfoRequestData->fileId] = queryInfoResponse->filename;
            } else {
                filename = constructGuidString(smbContext->currentQueryInfoRequestData->fileId);
            }
        }

        std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][filename];
        if (!serverFilePtr) {
            serverFilePtr = std::make_shared<SmbServerFile>();

            Fragment fragment;
            fragment.id = smbContext->offsetFile->getIdInIndex();
            fragment.start = 0;
            fragment.length = 0;
            serverFilePtr->fragments.push_back(fragment);
            serverFilePtr->setFilename(filename);
            serverFilePtr->setTimestamp(winFiletimeToTimePoint(queryInfoResponse->lastAccessTime));
            serverFilePtr->setProperty("protocol", "smb");
            serverFilePtr->setFiletype("smbserverfile");
            serverFilePtr->setOffsetType(smbContext->offsetFile->getFiletype());
            serverFilePtr->setProperty("srcIP", smbContext->offsetFile->getProperty("srcIP"));
            serverFilePtr->setProperty("dstIP", smbContext->offsetFile->getProperty("dstIP"));
            serverFilePtr->setProperty("srcPort", smbContext->offsetFile->getProperty("srcPort"));
            serverFilePtr->setProperty("dstPort", smbContext->offsetFile->getProperty("dstPort"));
            if (smbContext->treeNames.find(treeId) != smbContext->treeNames.end())
                serverFilePtr->setProperty("smbTree", smbContext->treeNames.at(treeId));
            serverFilePtr->flags.set(pcapfs::flags::PROCESSED);
            serverFilePtr->setFilesizeRaw(queryInfoResponse->filesize);
            serverFilePtr->setFilesizeProcessed(queryInfoResponse->filesize);
        } else {
            const TimePoint lastAccessTime = winFiletimeToTimePoint(queryInfoResponse->lastAccessTime);
            if (lastAccessTime > serverFilePtr->getTimestamp()) {
                serverFilePtr->setTimestamp(lastAccessTime);
                serverFilePtr->setFilesizeRaw(queryInfoResponse->filesize);
                serverFilePtr->setFilesizeProcessed(queryInfoResponse->filesize);
            }
        }
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


std::vector<pcapfs::FilePtr> pcapfs::smb::SmbManager::getServerFiles() {
    std::vector<FilePtr> resultVector;
    for (const auto &entry : serverFiles) {
        for (const auto& f : entry.second) {
            resultVector.push_back(f.second);
        }
    }

    return resultVector;
}
