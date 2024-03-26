#ifndef PCAPFS_VIRTUAL_FILES_SMBCONTROL_H
#define PCAPFS_VIRTUAL_FILES_SMBCONTROL_H

#include "virtualfile.h"


namespace pcapfs {

    class SmbControlFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SmbControlFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        void fillGlobalProperties(std::shared_ptr<SmbControlFile> &controlFilePtr, const FilePtr &filePtr);
        static bool isSmbOverTcp(const FilePtr &filePtr, const Bytes &data);
        static size_t getSmbOffsetAfterNbssSetup(const FilePtr &filePtr, const Bytes &data);

    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SMBCONTROL_H
