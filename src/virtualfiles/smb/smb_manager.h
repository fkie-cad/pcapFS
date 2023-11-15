#ifndef PCAPFS_SMB_MANAGER_H
#define PCAPFS_SMB_MANAGER_H

#include "smb_messages.h"
#include "../smb_serverfile.h"

namespace pcapfs {
    namespace smb {

        // map filename - FilePtr
        typedef std::unordered_map<std::string, SmbServerFilePtr> SmbServerFiles;
        // map treeId - tree name
        typedef std::unordered_map<uint32_t, std::string> SmbTreeNames;
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

            void updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext);
            void updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, const SmbContextPtr &smbContext);
            void updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, const SmbContextPtr &smbContext);
            std::vector<FilePtr> const getServerFiles();
            SmbServerFilePtr const getAsParentDirFile(const std::string &filePath, const std::shared_ptr<smb::SmbContext> &smbContext);

            void addTreeNameMapping(const ServerEndpoint &endp, uint32_t treeId, const std::string &treeName);

            SmbFileHandles const getFileHandles(const SmbContextPtr &smbContext) {
                                                return fileHandles[ServerEndpointTree(smbContext->serverEndpoint, smbContext->currentTreeId)]; };

            uint64_t getNewId();

        private:
            SmbManager() {}
            std::string const constructTreeString(const ServerEndpoint &endp, uint32_t treeId);
            std::map<ServerEndpointTree, SmbServerFiles> serverFiles;
            std::map<ServerEndpointTree, SmbFileHandles> fileHandles;
            std::map<ServerEndpoint, SmbTreeNames> treeNames;
            uint64_t idCounter = 0;
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
