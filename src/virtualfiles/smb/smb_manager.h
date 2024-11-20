#ifndef PCAPFS_SMB_MANAGER_H
#define PCAPFS_SMB_MANAGER_H

#include "smb_messages.h"
#include "../smb.h"
#include "smb_structs.h"

namespace pcapfs {
    namespace smb {

        // map filename - FilePtr
        typedef std::unordered_map<std::string, SmbFilePtr> SmbFiles;
        // map guid - filename
        typedef std::unordered_map<std::string, std::string> SmbFileHandles;

        class SmbManager {
        public:
            static SmbManager& getInstance() {
                static SmbManager instance;
                return instance;
            }

            SmbManager(SmbManager const&) = delete;
            void operator=(SmbManager const&) = delete;

            void extractMappings(const std::vector<FilePtr> &tcpFiles, const Index &idx, bool checkNonDefaultPorts);

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

            void setTimeOfNegResponse(const TimePoint &fsTime, const TimePoint &networkTime);
            void adjustSmbFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode);
            std::vector<FilePtr> const getSmbFiles(const Index &idx); // TODO: create abstract super function for that (its also needed by ftp)

            SmbFilePtr const getAsParentDirFile(const std::string &filePath, const SmbContextPtr &smbContext); // TODO: abstrahieren in global manager
            SmbFileHandles const getFileHandles(const SmbContextPtr &smbContext);

            uint64_t getNewId(); // TODO: move to abstract super class

            void serialize(boost::archive::text_oarchive &archive, const unsigned int&);
            void deserialize(boost::archive::text_iarchive &archive, const unsigned int&);

        private:
            SmbManager() {}

            void parseSmbConnectionMinimally(const FilePtr &tcpFile, const Bytes &data, size_t offsetAfterNbssSetup, uint16_t commandToParse);
            void parsePacketMinimally(const uint8_t* data, size_t len, uint16_t commandToParse, SmbContextPtr &smbContext);

            ServerEndpointTree const getServerEndpointTree(const SmbContextPtr &smbContext);

            // TODO: ABSTRAHIERE SERVERFILES ETC. IN ABSTRAKTEN SUPER-MANAGER
            std::map<ServerEndpointTree, SmbFiles> serverFiles; // in FTP, we have std::string instead of ServerEndpointTree

            std::map<ServerEndpointTree, SmbFileHandles> fileHandles;
            std::map<ServerEndpoint, SmbTreeNames> treeNames;
            uint64_t idCounter = 0; // TODO: move to abstract super class

            // first connectionBreak
            TimePoint oldestNetworkTimestamp = TimePoint::max(); // TODO: put into super class
            // last connectionBreak
            TimePoint newestNetworkTimestamp = TimePoint{}; // TODO: put into super class
            // networkTime , fsTime
            // (required for calculation of allowed snapshot range w.r.t. the fsTime)
            // TODO: neglect allowed range for fs timestamp mode!!!
            std::pair<TimePoint, TimePoint> timeOfOldestNegResponse = std::pair<TimePoint, TimePoint>(TimePoint::max(), TimePoint::max());
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
