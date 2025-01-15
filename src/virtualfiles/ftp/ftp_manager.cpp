#include "ftp_manager.h"
#include "../ftp.h"


void pcapfs::ftp::FtpManager::addFileTransmissionData(uint16_t port, const FileTransmissionData &data) {
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


std::vector<pcapfs::FileTransmissionData> pcapfs::ftp::FtpManager::getFileTransmissionData(uint16_t port) {
    DataMap::iterator it = data_transmissions.find(port);
    if (it != data_transmissions.end()) {
        return it->second;
    } else {
        return std::vector<FileTransmissionData>(0);
    }
}


pcapfs::ServerFilePtr const pcapfs::ftp::FtpManager::getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) {
    if (serverFiles[SERVER_FILE_TREE_DUMMY].find(filePath) != serverFiles[SERVER_FILE_TREE_DUMMY].end()) {
        LOG_DEBUG << "parent directory is already known as an FtpFile";
        return serverFiles[SERVER_FILE_TREE_DUMMY][filePath];
    } else {
        LOG_DEBUG << "parent directory not known as FtpFile yet, create parent dir file on the fly";
        FtpFilePtr newFtpDirFilePtr = std::make_shared<FtpFile>();
        newFtpDirFilePtr->handleAllFilesToRoot(filePath, context);
        newFtpDirFilePtr->fillGlobalProperties(context->offsetFile);
        newFtpDirFilePtr->setFilesizeRaw(0);
        newFtpDirFilePtr->setFilesizeProcessed(0);
        Fragment fragment;
        fragment.id = context->offsetFile->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        newFtpDirFilePtr->fragments.push_back(fragment);
        newFtpDirFilePtr->isDirectory = true;
        serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = newFtpDirFilePtr;
        return newFtpDirFilePtr;
    }
}


std::vector<pcapfs::FilePtr> const pcapfs::ftp::FtpManager::getServerFiles(const Index&) {
    std::vector<FilePtr> resultVector;
    std::transform(serverFiles[SERVER_FILE_TREE_DUMMY].begin(), serverFiles[SERVER_FILE_TREE_DUMMY].end(),
                    std::back_inserter(resultVector), [](const auto &f){ return f.second; });
    return resultVector;
}


void pcapfs::ftp::FtpManager::updateFtpFiles(const std::string &filePath, const FilePtr &offsetFilePtr) {
    FtpFilePtr ftpFilePtr = std::static_pointer_cast<FtpFile>(serverFiles[SERVER_FILE_TREE_DUMMY][filePath]);
    if (!ftpFilePtr) {
        ftpFilePtr = std::make_shared<FtpFile>();
        const ServerFileContextPtr context = std::make_shared<ServerFileContext>(offsetFilePtr);
        ftpFilePtr->handleAllFilesToRoot(filePath, context);
        ftpFilePtr->fillGlobalProperties(offsetFilePtr);
        ftpFilePtr->isDirectory = false;
        ftpFilePtr->parseResult(offsetFilePtr);
        serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = ftpFilePtr;
    } else if (ftpFilePtr->getFilesizeRaw() == 0) {
        // file is previously known only as empty file, now it's filled with content
        ftpFilePtr->flags.reset(flags::IS_METADATA);
        ftpFilePtr->parseResult(offsetFilePtr);
        serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = ftpFilePtr;
    }
}


void pcapfs::ftp::FtpManager::updateFtpFilesFromMlsd(const std::string &filePath, bool isDirectory, const TimePoint &modifyTime, const FilePtr &offsetFilePtr) {
    FtpFilePtr ftpFilePtr = std::static_pointer_cast<FtpFile>(serverFiles[SERVER_FILE_TREE_DUMMY][filePath]);
    if (ftpFilePtr) {
       ftpFilePtr->addFsTimestamp(offsetFilePtr->getTimestamp(), modifyTime);
    } else {
        ftpFilePtr = std::make_shared<FtpFile>();
        const ServerFileContextPtr context = std::make_shared<ServerFileContext>(offsetFilePtr);
        ftpFilePtr->handleAllFilesToRoot(filePath, context);
        ftpFilePtr->fillGlobalProperties(offsetFilePtr);
        ftpFilePtr->isDirectory = isDirectory;
        ftpFilePtr->addFsTimestamp(offsetFilePtr->getTimestamp(), modifyTime);
        Fragment fragment;
        fragment.id = offsetFilePtr->getIdInIndex();
        fragment.start = 0;
        fragment.length = 0;
        ftpFilePtr->fragments.push_back(fragment);
        ftpFilePtr->setFilesizeRaw(0);
        ftpFilePtr->setFilesizeProcessed(0);
        ftpFilePtr->flags.set(flags::IS_METADATA);
        serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = ftpFilePtr;
    }
}


// TODO: make this function once for all server files
void pcapfs::ftp::FtpManager::adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) {
    std::vector<pcapfs::FilePtr> filesToAdd;

    for (size_t i = indexFiles.size() - 1; i != (size_t)-1; --i) {
        FilePtr currFile = indexFiles.at(i);
        if (!currFile->isFiletype("ftp"))
            continue;

        pcapfs::FtpFilePtr ftpFilePtr = std::static_pointer_cast<pcapfs::FtpFile>(indexFiles.at(i));

        const std::vector<pcapfs::FilePtr> ftpFileVersions = ftpFilePtr->constructVersionFiles();
        //if (ftpFileVersions.size() != 0) {
        //    filesToAdd.insert(filesToAdd.end(), ftpFileVersions.begin(), ftpFileVersions.end());
        //    // old ftp file is not needed anymore since we now have all versions of it as separate files
        //    indexFiles.erase(indexFiles.begin()+i);
        //}
    }

    indexFiles.insert(indexFiles.end(), filesToAdd.begin(), filesToAdd.end());
}
