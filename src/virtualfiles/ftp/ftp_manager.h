#ifndef PCAPFS_FTP_MANAGER_H
#define PCAPFS_FTP_MANAGER_H

#include <map>
#include <string>
#include <vector>

#include "../ftpcontrol.h"
#include "../ftp.h"
#include "../../commontypes.h"


namespace pcapfs {

    class FtpManager {
    private:
        std::map<uint16_t, std::vector<FileTransmissionData>> data_transmissions;
        std::map<std::string, FtpFilePtr> ftpFiles;

    public:
        using DataMap = std::map<uint16_t, std::vector<FileTransmissionData>>;
        using DataMapPair = std::pair<uint16_t, std::vector<FileTransmissionData>>;

        static FtpManager &getInstance() {
            static FtpManager instance;
            return instance;
        }

        FtpManager(const FtpManager &) = delete;
        FtpManager(FtpManager &&) = delete;
        void operator=(const FtpManager &) = delete;

        void addFileTransmissionData(uint16_t port, const FileTransmissionData &data);
        std::vector<FileTransmissionData> getFileTransmissionData(uint16_t port);

        FtpFilePtr getAsParentDirFile(const std::string &filePath, const FilePtr &offsetFilePtr);
        uint64_t getNewId();

        void addFtpFile(const std::string &filePath, const FtpFilePtr &inFtpFile) { ftpFiles[filePath] = inFtpFile; };
        std::vector<FilePtr> getFtpFiles();

    private:
        FtpManager() {}
        uint64_t idCounter = 0;
    };
}

#endif //PCAPFS_FTP_MANAGER_H
