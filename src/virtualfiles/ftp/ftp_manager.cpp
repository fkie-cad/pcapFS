#include "ftp_manager.h"
#include "../ftp.h"


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
        newFtpDirFilePtr->setFilesizeRaw(0);
        newFtpDirFilePtr->setFilesizeProcessed(0);
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


void pcapfs::FtpManager::updateFtpFiles(const std::string &filePath, const FilePtr &offsetFilePtr) {
    FtpFilePtr ftpFilePtr = ftpFiles[filePath];
    if (!ftpFilePtr) {
        ftpFilePtr = std::make_shared<FtpFile>();
        ftpFilePtr->handleAllFilesToRoot(filePath, offsetFilePtr);
        ftpFilePtr->fillGlobalProperties(offsetFilePtr);
        ftpFilePtr->isDirectory = false;
        ftpFilePtr->parseResult(offsetFilePtr);
        ftpFiles[filePath] = ftpFilePtr;
    } else if (ftpFilePtr->getFilesizeRaw() == 0) {
        // file is previously known only as empty file, now it's filled with content
        ftpFilePtr->parseResult(offsetFilePtr);
        ftpFiles[filePath] = ftpFilePtr;
    }
}


void pcapfs::FtpManager::updateFtpFilesFromMlsd(const std::string &filePath, bool isDirectory, const TimePoint &modifyTime, const FilePtr &offsetFilePtr) {
    FtpFilePtr ftpFilePtr = ftpFiles[filePath];
    if (ftpFilePtr) {
        if (ftpFilePtr->getModifyTime() != modifyTime) {
            // file is already known, just update the timestamps
            LOG_TRACE << "updated modify time of" << filePath;
            ftpFilePtr->setModifyTime(modifyTime);
            ftpFilePtr->setAccessTime(modifyTime);
            ftpFilePtr->setChangeTime(modifyTime);
            ftpFiles[filePath] = ftpFilePtr;
        }
    } else {
        ftpFilePtr = std::make_shared<FtpFile>();
        ftpFilePtr->handleAllFilesToRoot(filePath, offsetFilePtr);
        ftpFilePtr->fillGlobalProperties(offsetFilePtr);
        ftpFilePtr->isDirectory = isDirectory;
        ftpFilePtr->setModifyTime(modifyTime);
        ftpFilePtr->setAccessTime(modifyTime);
        ftpFilePtr->setChangeTime(modifyTime);
        Fragment fragment;
        fragment.id = offsetFilePtr->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        ftpFilePtr->fragments.push_back(fragment);
        ftpFilePtr->setFilesizeRaw(0);
        ftpFilePtr->setFilesizeProcessed(0);
        ftpFiles[filePath] = ftpFilePtr;
    }
}
