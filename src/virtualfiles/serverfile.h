#ifndef PCAPFS_VIRTUAL_FILES_SERVERFILE_H
#define PCAPFS_VIRTUAL_FILES_SERVERFILE_H

#include "virtualfile.h"


namespace pcapfs {

    class ServerFile : public VirtualFile {
    public:
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override = 0;

        TimePoint const getAccessTime() { return accessTime; };
        TimePoint const getModifyTime() { return modifyTime; };
        TimePoint const getChangeTime() { return changeTime; };
        TimePoint const getBirthTime() { return birthTime; };
        std::shared_ptr<ServerFile> const getParentDir() { return parentDir; };

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        bool isDirectory;

    protected:
        TimePoint accessTime;
        TimePoint modifyTime;
        TimePoint changeTime;
        TimePoint birthTime;
        std::shared_ptr<ServerFile> parentDir = nullptr;
    };

    typedef std::shared_ptr<ServerFile> ServerFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SERVERFILE_H
