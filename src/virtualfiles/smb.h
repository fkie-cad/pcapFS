#ifndef PCAPFS_VIRTUAL_FILES_SMB_H
#define PCAPFS_VIRTUAL_FILES_SMB_H

#include "virtualfile.h"
#include "smb/smb_headers.h"


namespace pcapfs {

    class SmbFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SmbFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        void fillGlobalProperties(std::shared_ptr<SmbFile> &controlFilePtr, const FilePtr &filePtr);
        static bool isSmbTraffic(const FilePtr &filePtr, const Bytes &data);

    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
