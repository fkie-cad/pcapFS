#ifndef PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H
#define PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H

#include "virtualfile.h"
#include "../filefactory.h"
#include "smb/smb_constants.h"


namespace pcapfs {

    class SmbServerFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SmbServerFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void initializeFilePtr(const std::shared_ptr<smb::SmbContext> &smbContext, const std::string &inFilename,
                                uint64_t lastAccessTime, uint64_t inFilesize, uint32_t treeId);

    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H
