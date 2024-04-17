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

            void updateSmbFiles(const std::shared_ptr<CreateResponse> &createResponse, SmbContextPtr &smbContext, uint64_t messageId);
            void updateSmbFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext, uint64_t messageId);
            void updateSmbFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext, uint64_t messageId);
            void updateSmbFiles(const std::shared_ptr<ReadResponse> &readResponse, const SmbContextPtr &smbContext, uint64_t messageId);
            void updateSmbFiles(const std::shared_ptr<WriteRequest> &writeRequest, const SmbContextPtr &smbContext);

            std::vector<FilePtr> const getSmbFiles();
            SmbFilePtr const getAsParentDirFile(const std::string &filePath, const SmbContextPtr &smbContext);
            SmbFileHandles const getFileHandles(const SmbContextPtr &smbContext);
            uint64_t getNewId();

        private:
            SmbManager() {}
            std::map<ServerEndpointTree, SmbFiles> serverFiles;
            std::map<ServerEndpointTree, SmbFileHandles> fileHandles;
            uint64_t idCounter = 0;
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
