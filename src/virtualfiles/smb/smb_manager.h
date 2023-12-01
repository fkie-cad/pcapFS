#ifndef PCAPFS_SMB_MANAGER_H
#define PCAPFS_SMB_MANAGER_H

#include "smb_messages.h"
#include "../smb_serverfile.h"
#include "smb_structs.h"

namespace pcapfs {
    namespace smb {

        // map filename - FilePtr
        typedef std::unordered_map<std::string, SmbServerFilePtr> SmbServerFiles;
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

            void updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, SmbContextPtr &smbContext);
            void updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext);
            void updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, SmbContextPtr &smbContext);
            std::vector<FilePtr> const getServerFiles();
            SmbServerFilePtr const getAsParentDirFile(const std::string &filePath, SmbContextPtr &smbContext);


            SmbFileHandles const getFileHandles(const SmbContextPtr &smbContext);

            uint64_t getNewId();

        private:
            SmbManager() {}
            std::map<ServerEndpointTree, SmbServerFiles> serverFiles;
            std::map<ServerEndpointTree, SmbFileHandles> fileHandles;
            uint64_t idCounter = 0;
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
