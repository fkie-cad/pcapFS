#ifndef PCAPFS_FTP_MANAGER_H
#define PCAPFS_FTP_MANAGER_H

#include <map>
#include <string>
#include <vector>

#include "../serverfile_manager.h"
#include "../ftpcontrol.h"
#include "../ftp.h"
#include  "ftp_utils.h"
#include "../../commontypes.h"


namespace pcapfs {
    namespace ftp {
        class FtpManager : public ServerFileManager {
        private:
            std::map<uint16_t, std::vector<FtpFileTransmissionData>> data_transmissions;

        public:
            using DataMap = std::map<uint16_t, std::vector<FtpFileTransmissionData>>;
            using DataMapPair = std::pair<uint16_t, std::vector<FtpFileTransmissionData>>;

            static FtpManager &getInstance() {
                static FtpManager instance;
                return instance;
            }

            FtpManager(const FtpManager &) = delete;
            FtpManager(FtpManager &&) = delete;
            void operator=(const FtpManager &) = delete;

            void addFileTransmissionData(uint16_t port, const FtpFileTransmissionData &data);
            std::vector<FtpFileTransmissionData> getFileTransmissionData(uint16_t port);

            ServerFilePtr const getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) override;
            std::vector<FilePtr> const getServerFiles(const Index&) override;
            void adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) override;

            void addFtpFile(const std::string &filePath, const FtpFilePtr &inFtpFile) { serverFiles[SERVER_FILE_TREE_DUMMY][filePath] = inFtpFile; };

            void updateFtpFiles(const std::string &filePath, const std::string &command, const FilePtr &offsetFilePtr);
            void updateFtpFilesFromMlsd(const std::string &filePath, bool isDirectory, const TimePoint &modifyTime, const FilePtr &offsetFilePtr);
            void updateFtpFilesFromMlst(const std::string &filePath, const FtpResponse &response, const FilePtr &offsetFilePtr);

        private:
            FtpManager() {}
        };
    }
}

#endif //PCAPFS_FTP_MANAGER_H
