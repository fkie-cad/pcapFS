#ifndef PCAPFS_VIRTUAL_FILES_SERVERFILE_H
#define PCAPFS_VIRTUAL_FILES_SERVERFILE_H

#include "virtualfile.h"
#include <set>


namespace pcapfs {

    class ServerFile : public VirtualFile {
    public:
        ServerFile() { flags.set(flags::IS_SERVERFILE); };

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override = 0;

        TimePoint const getAccessTime() { return accessTime; };
        TimePoint const getModifyTime() { return modifyTime; };
        TimePoint const getChangeTime() { return changeTime; };
        TimePoint const getBirthTime() { return birthTime; };
        uint64_t getParentDirId() { return parentDirId; };
        FilePtr const getParentDir() { return parentDir; };
        std::set<std::string> const getClientIPs() { return clientIPs; };

        void setAccessTime(const TimePoint &inTime) { accessTime = inTime; };
        void setModifyTime(const TimePoint &inTime) { modifyTime = inTime; };
        void setChangeTime(const TimePoint &inTime) { changeTime = inTime; };
        void setParentDir(const FilePtr &serverFile) { parentDir = serverFile; };
        void setClientIPs(const std::set<std::string> &inClientIPs) {clientIPs = inClientIPs; };
        void addClientIP(const std::string &ip) { clientIPs.insert(ip); };
        void clearAndAddClientIP(const std::string &ip) {
            clientIPs.clear();
            clientIPs.insert(ip);
        };

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        std::vector<std::shared_ptr<ServerFile>> getAllParentDirs();

        bool isDirectory;

    protected:
        TimePoint accessTime = TimePoint{};
        TimePoint modifyTime = TimePoint{};
        TimePoint changeTime = TimePoint{};
        TimePoint birthTime = TimePoint{};
        std::set<std::string> clientIPs;
        uint64_t parentDirId = 0;
        FilePtr parentDir = nullptr;
    };

    typedef std::shared_ptr<ServerFile> ServerFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SERVERFILE_H
