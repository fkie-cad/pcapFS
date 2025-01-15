#ifndef PCAPFS_FTP_MANAGER_H
#define PCAPFS_FTP_MANAGER_H

#include <map>
#include <string>
#include <vector>

#include "../serverfile_manager.h"
#include "../ftpcontrol.h"
#include "../ftp.h"
#include "../../commontypes.h"


namespace pcapfs {
    namespace ftp {
        class FtpManager : public ServerFileManager {
        private:
            std::map<uint16_t, std::vector<FileTransmissionData>> data_transmissions;

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

            ServerFilePtr const getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) override;
            std::vector<FilePtr> const getServerFiles(const Index&) override;
            void adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) override;

            void addFtpFile(const std::string &filePath, const FtpFilePtr &inFtpFile) { serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = inFtpFile; };

            void updateFtpFiles(const std::string &filePath, const FilePtr &offsetFilePtr);
            void updateFtpFilesFromMlsd(const std::string &filePath, bool isDirectory, const TimePoint &modifyTime, const FilePtr &offsetFilePtr);

        private:
            FtpManager() {}
        };
    }
}

#endif //PCAPFS_FTP_MANAGER_H
