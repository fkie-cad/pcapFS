#include "smb_manager.h"
#include "smb_utils.h"
#include "../smb.h"


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<CreateResponse> &createResponse, SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from create messages
    LOG_TRACE << "updating SMB server files with create response infos";

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
    const std::string filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.at(messageId);

    // update fileId-filename mapping
    fileHandles[endpointTree][createResponse->fileId] = filePath;

    if (!createResponse->metaData->isDirectory) {
        // this prevents possible wrong file path compositions in the other updateSmbFiles functions in the case that
        // currentCreateRequestFile is chosen as parent directory path of the respective server files although
        // it isn't even a directory
        smbContext->createRequestFileNames.at(messageId) = "";
    }

    if (!smbContext->createServerFiles)
        return;

    SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];
    if (!smbFilePtr) {
        // server file not present in map -> create new one
        LOG_TRACE << "file " << filePath << " is new and added to the server files";
        smbFilePtr = std::make_shared<SmbFile>();
        smbFilePtr->initializeFilePtr(smbContext, filePath, createResponse->metaData);
    } else {
        // server file is already known; update metadata if the current timestamp is newer
        const TimePoint lastAccessTime = winFiletimeToTimePoint(createResponse->metaData->lastAccessTime);
        if (lastAccessTime > smbFilePtr->getAccessTime()) {
            LOG_TRACE << "file " << filePath << " is already known and updated";
            smbFilePtr->setTimestamp(lastAccessTime);
            smbFilePtr->setAccessTime(lastAccessTime);
            smbFilePtr->setModifyTime(smb::winFiletimeToTimePoint(createResponse->metaData->lastWriteTime));
            smbFilePtr->setChangeTime(smb::winFiletimeToTimePoint(createResponse->metaData->changeTime));
        }
    }

    serverFiles[endpointTree][filePath] = smbFilePtr;
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext, uint64_t messageId) {
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
                // update fileId-filename mapping
                fileHandles[endpointTree][currentQueryInfoRequestData->fileId] = filePath;

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
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(queryInfoResponse->metaData->lastAccessTime);
            if (lastAccessTime > smbFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                smbFilePtr->setTimestamp(lastAccessTime);
                smbFilePtr->setAccessTime(lastAccessTime);
                smbFilePtr->setModifyTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->lastWriteTime));
                smbFilePtr->setChangeTime(smb::winFiletimeToTimePoint(queryInfoResponse->metaData->changeTime));
            }
        }

        serverFiles[endpointTree][filePath] = smbFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext, uint64_t messageId) {
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
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + smbContext->createRequestFileNames.rbegin()->second + "\\" + fileInfo->filename;
        } else if (!smbContext->createRequestFileNames.empty() && smbContext->createRequestFileNames.rbegin()->second.empty()) {
            // probably root directory of the tree
            // this could produce wrong result
            filePath = smbContext->treeNames[smbContext->currentTreeId] + "\\" + fileInfo->filename;
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
            // server file is already known; update metadata if the current timestamp is newer
            const TimePoint lastAccessTime = winFiletimeToTimePoint(fileInfo->metaData->lastAccessTime);
            if (lastAccessTime > smbFilePtr->getAccessTime()) {
                LOG_TRACE << "file " << filePath << " is already known and updated";
                smbFilePtr->setTimestamp(lastAccessTime);
                smbFilePtr->setAccessTime(lastAccessTime);
                smbFilePtr->setModifyTime(smb::winFiletimeToTimePoint(fileInfo->metaData->lastWriteTime));
                smbFilePtr->setChangeTime(smb::winFiletimeToTimePoint(fileInfo->metaData->changeTime));
            }
        }

        serverFiles[endpointTree][filePath] = smbFilePtr;
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<ReadResponse> &readResponse, const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file infos obtained from read messages

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
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
            serverFiles[endpointTree][filePath] = smbFilePtr;

        } else if (currentReadRequestData->readOffset == 0) {
            // create new file version (backup old file version)
            LOG_TRACE << "create new file version";

            // backup current file version
            SmbFilePtr oldVersion(smbFilePtr->clone());
            // we need to change IdInIndex s.t. it becomes a uniquely indexable file
            oldVersion->setIdInIndex(smb::SmbManager::getInstance().getNewId());
            // update filename and filePath
            const std::string tag = "@" + std::to_string(oldVersion->getFileVersion());
            oldVersion->setFilename(oldVersion->getFilename() + tag);
            oldVersion->flags.reset(flags::IS_METADATA);
            const std::string newFilePath = filePath + tag;
            serverFiles[endpointTree][newFilePath] = oldVersion;

            // add new Fragment for current file
            smbFilePtr->fragments.clear();
            smbFilePtr->fragments.push_back(newFragment);
            smbFilePtr->setFileVersion(smbFilePtr->getFileVersion()+1); // increase file version
            smbFilePtr->setFilesizeRaw(newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);
            serverFiles[endpointTree][filePath] = smbFilePtr;
        }
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const std::shared_ptr<WriteRequest> &writeRequest, const SmbContextPtr &smbContext) {
    // update server files with file infos obtained from write messages

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
    if (fileHandles[endpointTree].find(writeRequest->fileId) == fileHandles[endpointTree].end()) {
        // fileId - filename mapping not known
        return;
    }

    const std::string filePath = fileHandles[endpointTree].at(writeRequest->fileId);
    if (serverFiles[endpointTree].find(filePath) == serverFiles[endpointTree].end() || !serverFiles[endpointTree].at(filePath)) {
        // should not happen
        return;
    }

    LOG_TRACE << "updating SMB server files with write message infos";
    LOG_TRACE << "file to update: " << filePath;

    Fragment newFragment;
    newFragment.id = smbContext->offsetFile->getIdInIndex();
    newFragment.start = smbContext->currentOffset + writeRequest->dataOffset;
    newFragment.length = writeRequest->writeLength;

    SmbFilePtr smbFilePtr = serverFiles[endpointTree][filePath];

    if (smbFilePtr->getFilesizeRaw() == 0 && writeRequest->writeOffset == 0) {
        // no fragments with file content are saved yet and we have writeOffset 0
        LOG_TRACE << "no fragments are saved yet, writeOffset == 0";
        smbFilePtr->fragments.push_back(newFragment);
        smbFilePtr->setFilesizeRaw(newFragment.length);
        smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
        smbFilePtr->flags.reset(flags::IS_METADATA);
        serverFiles[endpointTree][filePath] = smbFilePtr;

    } else if (smbFilePtr->getFilesizeRaw() != 0) {
        // we have already some saved fragments for that file
        // (we only allow following adjacent fragments or fragments at the beginning of the file)

        if (writeRequest->writeOffset == smbFilePtr->getFilesizeRaw()) {
            // append fragment to file
            LOG_TRACE << "some fragments are already saved, append new fragment";
            smbFilePtr->fragments.push_back(newFragment);
            smbFilePtr->setFilesizeRaw(writeRequest->writeOffset + newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);
            serverFiles[endpointTree][filePath] = smbFilePtr;

        } else if (writeRequest->writeOffset == 0) {
            // create new file version (backup old file version)
            LOG_TRACE << "create new file version";

            // backup current file version
            SmbFilePtr oldVersion(smbFilePtr->clone());
            // we need to change IdInIndex s.t. it becomes a uniquely indexable file
            oldVersion->setIdInIndex(smb::SmbManager::getInstance().getNewId());
            // update filename and filePath
            const std::string tag = "@" + std::to_string(oldVersion->getFileVersion());
            oldVersion->setFilename(oldVersion->getFilename() + tag);
            oldVersion->flags.reset(flags::IS_METADATA);
            const std::string newFilePath = filePath + tag;
            serverFiles[endpointTree][newFilePath] = oldVersion;

            // add new Fragment for current file
            smbFilePtr->fragments.clear();
            smbFilePtr->fragments.push_back(newFragment);
            smbFilePtr->setFileVersion(smbFilePtr->getFileVersion()+1); // increase file version
            smbFilePtr->setFilesizeRaw(newFragment.length);
            smbFilePtr->setFilesizeProcessed(smbFilePtr->getFilesizeRaw());
            smbFilePtr->flags.reset(flags::IS_METADATA);
            serverFiles[endpointTree][filePath] = smbFilePtr;
        }
    }
}


void pcapfs::smb::SmbManager::updateSmbFiles(const SmbContextPtr &smbContext, uint64_t messageId) {
    // update server files with file metadata obtained from set info message

    const std::shared_ptr<SetInfoRequestData> setInfoRequestData = smbContext->setInfoRequestData[messageId];

    const ServerEndpointTree endpointTree = smbContext->getServerEndpointTree();
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

    // a value of zero means the SMB server must not change this attribute
    if (setInfoRequestData->metaData->lastAccessTime != 0) {
        const auto lastAccessTime = smb::winFiletimeToTimePoint(setInfoRequestData->metaData->lastAccessTime);
        smbFilePtr->setTimestamp(lastAccessTime);
        smbFilePtr->setAccessTime(lastAccessTime);
    }
    if (setInfoRequestData->metaData->lastWriteTime != 0)
        smbFilePtr->setModifyTime(smb::winFiletimeToTimePoint(setInfoRequestData->metaData->lastWriteTime));
    if (setInfoRequestData->metaData->changeTime != 0)
        smbFilePtr->setChangeTime(smb::winFiletimeToTimePoint(setInfoRequestData->metaData->changeTime));

    serverFiles[endpointTree][filePath] = smbFilePtr;

}


pcapfs::smb::SmbFileHandles const pcapfs::smb::SmbManager::getFileHandles(const SmbContextPtr &smbContext) {
    return fileHandles[smbContext->getServerEndpointTree()];
}


pcapfs::SmbFilePtr const pcapfs::smb::SmbManager::getAsParentDirFile(const std::string &filePath, const SmbContextPtr &smbContext) {
    const ServerEndpointTree endpt = smbContext->getServerEndpointTree();
    if (serverFiles[endpt].find(filePath) != serverFiles[endpt].end()) {
        LOG_DEBUG << "parent directory is already known as an SmbFile";
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
    std::map<std::string, std::vector<SmbFilePtr>> fileVersions;

    LOG_DEBUG << "Collecting all SMB files...";
    for (const auto &endpt : serverFiles) {
        for (auto &fileEntry: endpt.second) {
            if (!fileEntry.second->flags.test(flags::IS_METADATA)) {
                // pick files with multiple versions for extra check later
                if (fileEntry.first.rfind('@') != std::string::npos) {
                    fileVersions[std::string(fileEntry.first.begin(), fileEntry.first.begin()+fileEntry.first.rfind('@'))].push_back(fileEntry.second);
                } else if (fileEntry.second->getFileVersion() != 0 && fileEntry.first.rfind('@') == std::string::npos) {
                    // for newest version, we also need to set the version tag in the file name since we didn't do that before
                    fileEntry.second->setFilename(fileEntry.second->getFilename() + "@" + std::to_string(fileEntry.second->getFileVersion()));
                    fileVersions[fileEntry.first].push_back(fileEntry.second);
                } else {
                    // no versions detected -> add directly to resultVector
                    resultVector.push_back(fileEntry.second);
                }
            } else {
                resultVector.push_back(fileEntry.second);
            }
        }
    }

    // deduplicate redundant successive versions
    for (auto &entry : fileVersions) {
        LOG_TRACE << "checking redundant successive versions of " << entry.first;
        // sort versions in ascending order
        std::sort(entry.second.begin(), entry.second.end(), [](const auto &a, const auto &b){ return a->getFileVersion() < b->getFileVersion(); });
        uint64_t tmpFilesizeRaw = entry.second.at(0)->getFilesizeRaw();
        Bytes buf;
        Bytes cmpBuf(tmpFilesizeRaw);
        entry.second.at(0)->read(0, tmpFilesizeRaw, idx, (char*) cmpBuf.data());
        for (uint32_t i = 1; i < entry.second.size(); ++i) {
            tmpFilesizeRaw = entry.second.at(i)->getFilesizeRaw();
            buf.resize(tmpFilesizeRaw);
            entry.second.at(i)->read(0, tmpFilesizeRaw, idx, (char*) buf.data());
            if (buf == cmpBuf) {
                LOG_TRACE << "Versions " << i-1 << " and " << i << " are the same -> deduplicate";
                entry.second.erase(entry.second.begin()+i);
            }
            cmpBuf.assign(buf.begin(), buf.end());
        }

        // adjust file versions so that they are consecutive again
        for (uint32_t j = 0; j < entry.second.size(); ++j) {
            if (j != entry.second.at(j)->getFileVersion()) {
                entry.second.at(j)->setFileVersion(j);
                const std::string oldFilename = entry.second.at(j)->getFilename();
                entry.second.at(j)->setFilename(std::string(oldFilename.begin(), oldFilename.begin()+oldFilename.rfind('@')+1) + std::to_string(j));
            }
        }

        // remove tag in file name when the number of deduplcated versions reduced to 1
        if (entry.second.size() == 1) {
            const std::string oldFilename = entry.second.at(0)->getFilename();
            entry.second.at(0)->setFilename(std::string(oldFilename.begin(), oldFilename.begin() + oldFilename.rfind('@')));
        }

        resultVector.insert(resultVector.end(), entry.second.begin(), entry.second.end());
    }

    return resultVector;
}
