#include "ftp_manager.h"


void pcapfs::FtpManager::addFileTransmissionData(uint16_t port, const FileTransmissionData &data) {
    LOG_DEBUG << "FTP: add file transmission data for file " << data.transmission_file;
    DataMap::iterator it = data_transmissions.find(port);
    if (it == data_transmissions.end()) {
        std::vector<FileTransmissionData> files;
        files.emplace_back(data);
        data_transmissions.insert(DataMapPair(port, files));
    } else {
        it->second.emplace_back(data);
    }
}


std::vector<pcapfs::FileTransmissionData> pcapfs::FtpManager::getFileTransmissionData(uint16_t port) {
    DataMap::iterator it = data_transmissions.find(port);
    if (it != data_transmissions.end()) {
        return it->second;
    } else {
        return std::vector<FileTransmissionData>(0);
    }
}


pcapfs::FtpFilePtr pcapfs::FtpManager::getAsParentDirFile(const std::string &filePath, const FilePtr &offsetFilePtr) {
    if (ftpFiles.find(filePath) != ftpFiles.end()) {
        LOG_DEBUG << "parent directory is already known as an FtpFile";
        return ftpFiles[filePath];
    } else {
        LOG_DEBUG << "parent directory not known as FtpFile yet, create parent dir file on the fly";
        FtpFilePtr newFtpDirFilePtr = std::make_shared<FtpFile>();
        newFtpDirFilePtr->handleAllFilesToRoot(filePath, offsetFilePtr);
        newFtpDirFilePtr->fillGlobalProperties(offsetFilePtr);
        Fragment fragment;
        fragment.id = offsetFilePtr->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        newFtpDirFilePtr->fragments.push_back(fragment);
        newFtpDirFilePtr->isDirectory = true;
        ftpFiles[filePath] = newFtpDirFilePtr;
        return newFtpDirFilePtr;
    }
}


uint64_t pcapfs::FtpManager::getNewId() {
    const uint64_t newId = idCounter;
    idCounter++;
    return newId;
}


std::vector<pcapfs::FilePtr> pcapfs::FtpManager::getFtpFiles() {
    std::vector<FilePtr> resultVector;
    std::transform(ftpFiles.begin(), ftpFiles.end(), std::back_inserter(resultVector), [](const auto &f){ return f.second; });
    return resultVector;
}
