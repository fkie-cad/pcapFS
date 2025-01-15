#ifndef PCAPFS_SMB_MANAGER_H
#define PCAPFS_SMB_MANAGER_H

#include "../serverfile_manager.h"
#include "smb_messages.h"
#include "../smb.h"
#include "smb_structs.h"

namespace pcapfs {
    namespace smb {

        // map guid - filename
        typedef std::unordered_map<std::string, std::string> SmbFileHandles;

        class SmbManager : public ServerFileManager {
        public:
            static SmbManager& getInstance() {
                static SmbManager instance;
                return instance;
            }

            SmbManager(SmbManager const&) = delete;
            void operator=(SmbManager const&) = delete;

            std::vector<FilePtr> const getServerFiles(const Index &idx) override;
            ServerFilePtr const getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) override;

            void extractMappings(const std::vector<FilePtr> &tcpFiles, const Index &idx, bool checkNonDefaultPorts);
            void setTimeOfNegResponse(const TimePoint &fsTime, const TimePoint &networkTime);
            SmbFileHandles const getFileHandles(const SmbContextPtr &smbContext);
            void adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) override;

            // SMB2_QUERY_INFO Response
            void updateSmbFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext, uint64_t messageId);
            // SMB2_QUERY_DIRECTORY Response
            void updateSmbFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext, uint64_t messageId);
            // SMB2_READ Response
            void updateSmbFiles(const std::shared_ptr<ReadResponse> &readResponse, const SmbContextPtr &smbContext, uint64_t messageId);
            // SMB2_WRITE Request
            void updateSmbFiles(const std::shared_ptr<WriteRequestData> &writeRequestData, const SmbContextPtr &smbContext);
            // SMB2_SET_INFO Request
            void updateSmbFiles(const SmbContextPtr &smbContext, uint64_t messageId);
            // SMB2_CLOSE Response
            void updateSmbFiles(const std::string &fileId, const FileMetaDataPtr &metaData, const SmbContextPtr &smbContext);

            void serialize(boost::archive::text_oarchive &archive, const unsigned int&);
            void deserialize(boost::archive::text_iarchive &archive, const unsigned int&);

        private:
            SmbManager() {}

            void parseSmbConnectionMinimally(const FilePtr &tcpFile, const Bytes &data, size_t offsetAfterNbssSetup, uint16_t commandToParse);
            void parsePacketMinimally(const uint8_t* data, size_t len, uint16_t commandToParse, SmbContextPtr &smbContext);

            ServerEndpointTree const getServerEndpointTree(const SmbContextPtr &smbContext);

            std::map<ServerEndpointTree, SmbFileHandles> fileHandles;
            std::map<ServerEndpoint, SmbTreeNames> treeNames;

            // first connectionBreak
            TimePoint oldestNetworkTimestamp = TimePoint::max();
            // last connectionBreak
            TimePoint newestNetworkTimestamp = TimePoint{};
            // networkTime , fsTime
            // (required for calculation of allowed snapshot range w.r.t. the fsTime)
            std::pair<TimePoint, TimePoint> timeOfOldestNegResponse = std::pair<TimePoint, TimePoint>(TimePoint::max(), TimePoint::max());
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
