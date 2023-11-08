#ifndef PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H
#define PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H

#include "serverfile.h"
#include "../filefactory.h"
#include "smb/smb_structs.h"


namespace pcapfs {

    class SmbServerFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<SmbServerFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void initializeFilePtr(const std::shared_ptr<smb::SmbContext> &smbContext, const std::string &filePath,
                                const smb::FileMetaDataPtr &metaData);

    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<SmbServerFile> SmbServerFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_SERVERFILE_H
