#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb_serverfile.h"


void pcapfs::smb::SmbManager::updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext, uint32_t treeId) {
    const ServerEndpoint endpoint = getServerEndpoint(smbContext->offsetFile, treeId);
    std::shared_ptr<SmbServerFile> serverFilePtr = serverFiles[endpoint][smbContext->currentRequestedFile];
    if (!serverFilePtr) {
        serverFilePtr = std::make_shared<SmbServerFile>();

        Fragment fragment;
        fragment.id = smbContext->offsetFile->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        serverFilePtr->fragments.push_back(fragment);
        serverFilePtr->setFilename(smbContext->currentRequestedFile);
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

    serverFiles[endpoint][smbContext->currentRequestedFile] = serverFilePtr;
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
