#ifndef PCAPFS_VIRTUAL_FILES_SMB_H
#define PCAPFS_VIRTUAL_FILES_SMB_H

#include "virtualfile.h"


namespace pcapfs {

    class SmbFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SmbFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void setFileContent(const std::string &content) { fileContent = content; };

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

    private:
        void fillGlobalProperties(std::shared_ptr<SmbFile> &controlFilePtr, const FilePtr &filePtr);
        static bool isSmbOverTcp(const FilePtr &filePtr, const Bytes &data);
        static size_t getSmbOffsetAfterNbssSetup(const FilePtr &filePtr, const Bytes &data);

        std::string fileContent = "";

    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
