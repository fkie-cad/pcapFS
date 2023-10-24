#ifndef PCAPFS_SMB_MANAGER_H
#define PCAPFS_SMB_MANAGER_H

#include "smb_messages.h"
#include "smb_constants.h"
#include "../smb_serverfile.h"
#include "../../commontypes.h"
#include "../../file.h"

namespace pcapfs {
    namespace smb {

        // map filename - FilePtr
        typedef std::map<std::string, std::shared_ptr<SmbServerFile>> SmbServerFiles;

        class SmbManager {
        public:
            static SmbManager& getInstance() {
                static SmbManager instance;
                return instance;
            }

            SmbManager(SmbManager const&) = delete;
            void operator=(SmbManager const&) = delete;

            void updateServerFiles(const std::shared_ptr<CreateResponse> &createResponse, const SmbContextPtr &smbContext, uint32_t treeId);
            void updateServerFiles(const std::shared_ptr<QueryInfoResponse> &queryInfoResponse, SmbContextPtr &smbContext, uint32_t treeId);
            void updateServerFiles(const std::vector<std::shared_ptr<FileInformation>> &fileInfos, SmbContextPtr &smbContext, uint32_t treeId);
            std::vector<FilePtr> const getServerFiles();

        private:
            SmbManager() {}
            ServerEndpoint const getServerEndpoint(const FilePtr &filePtr, uint32_t treeId);
            std::map<ServerEndpoint, SmbServerFiles> serverFiles;
        };
    }
}

#endif // PCAPFS_SMB_MANAGER_H
