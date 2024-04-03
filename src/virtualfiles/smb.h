#ifndef PCAPFS_VIRTUAL_FILES_SMB_H
#define PCAPFS_VIRTUAL_FILES_SMB_H

#include "serverfile.h"
#include "../filefactory.h"
#include "smb/smb_structs.h"


namespace pcapfs {

    class SmbFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<SmbFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void initializeFilePtr(smb::SmbContextPtr &smbContext, const std::string &filePath,
                                const smb::FileMetaDataPtr &metaData);

        void setFileVersion(uint64_t num) { fileVersion = num; };
        uint64_t getFileVersion() { return fileVersion; };

        SmbFile* clone() { return new SmbFile(*this); };

    private:
        uint64_t fileVersion = 0;
    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<SmbFile> SmbFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
