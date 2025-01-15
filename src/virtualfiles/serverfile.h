#ifndef PCAPFS_VIRTUAL_FILES_SERVERFILE_H
#define PCAPFS_VIRTUAL_FILES_SERVERFILE_H

#include "virtualfile.h"
#include <set>


namespace pcapfs {

    struct ServerFileContext {
        explicit ServerFileContext(const FilePtr &inOffsetFile) : offsetFile(inOffsetFile) {}
        FilePtr offsetFile = nullptr;
    };
    typedef std::shared_ptr<ServerFileContext> ServerFileContextPtr;


    struct TimeTriple {
        TimeTriple(){}
        TimeTriple(const TimePoint &inHybridTime, const TimePoint &inFsTime, const TimePoint &inNetworkTime) :
                        hybridTime(inHybridTime), fsTime(inFsTime), networkTime(inNetworkTime) {}
        TimePoint hybridTime = TimePoint{};
        TimePoint fsTime = TimePoint{};
        TimePoint networkTime = TimePoint{};

        bool operator<(const TimeTriple &tp) const {
            if (hybridTime == tp.hybridTime)
                return (fsTime == tp.fsTime) ? networkTime < tp.networkTime : fsTime < tp.fsTime;
            else
                return hybridTime < tp.hybridTime;
        };

        bool operator==(const TimeTriple &tp) const {
            return hybridTime == tp.hybridTime && fsTime == tp.fsTime && networkTime == tp.networkTime;
        };

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & hybridTime;
            archive & fsTime;
            archive & networkTime;
        }
    };


    struct ServerFileTimestamps {
        ServerFileTimestamps() {}
        ServerFileTimestamps(const TimePoint &inAccessTime, const TimePoint &inModifyTime, const TimePoint &inChangeTime,
                        const TimePoint &inBirthTime) :
                        accessTime(inAccessTime), modifyTime(inModifyTime), changeTime(inChangeTime),
                        birthTime(inBirthTime) {}
        TimePoint accessTime = TimePoint{};
        TimePoint modifyTime = TimePoint{};
        TimePoint changeTime = TimePoint{};
        TimePoint birthTime = TimePoint{};

        bool operator<(const ServerFileTimestamps &tp) const {
            if (accessTime == tp.accessTime)
                if (modifyTime == tp.modifyTime)
                        return changeTime < tp.changeTime;
                else
                    return modifyTime < tp.modifyTime;
            else
                return accessTime < tp.accessTime;
        };

        bool operator==(const ServerFileTimestamps &tp) const {
            return accessTime == tp.accessTime && modifyTime == tp.modifyTime &&
                    changeTime == tp.changeTime && birthTime == tp.birthTime;
        };

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & accessTime;
            archive & modifyTime;
            archive & changeTime;
            archive & birthTime;
        }
    };


    struct ServerFileVersion {
        ServerFileVersion() {}
        ServerFileVersion(const std::vector<Fragment> &inFragments, const std::set<std::string> &inClientIPs, bool inReadOperation)
                        : fragments(inFragments), clientIPs(inClientIPs), readOperation(inReadOperation) {}
        std::vector<Fragment> fragments;
        std::set<std::string> clientIPs;
        bool readOperation = false;
        std::set<TimeTriple> accesses;

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & fragments;
            archive & clientIPs;
            archive & accesses;
            archive & readOperation;
        }
    };


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

        virtual std::vector<FilePtr> const constructVersionFiles() = 0;
        virtual bool constructSnapshotFile() = 0;

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
