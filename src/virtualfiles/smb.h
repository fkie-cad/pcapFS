#ifndef PCAPFS_VIRTUAL_FILES_SMB_H
#define PCAPFS_VIRTUAL_FILES_SMB_H

#include "serverfile.h"
#include "../filefactory.h"
#include "smb/smb_structs.h"



namespace pcapfs {

    struct SmbTimeTriple {
        // TODO: abstrahiere SmbTimeTriple
        SmbTimeTriple(){}
        SmbTimeTriple(const TimePoint &inHybridTime, const TimePoint &inFsTime, const TimePoint &inNetworkTime) :
                        hybridTime(inHybridTime), fsTime(inFsTime), networkTime(inNetworkTime) {}
        TimePoint hybridTime = TimePoint{};
        TimePoint fsTime = TimePoint{};
        TimePoint networkTime = TimePoint{};

        bool operator<(const SmbTimeTriple &tp) const {
            if (hybridTime == tp.hybridTime)
                return (fsTime == tp.fsTime) ? networkTime < tp.networkTime : fsTime < tp.fsTime;
            else
                return hybridTime < tp.hybridTime;
        };

        bool operator==(const SmbTimeTriple &tp) const {
            return hybridTime == tp.hybridTime && fsTime == tp.fsTime && networkTime == tp.networkTime;
        };

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & hybridTime;
            archive & fsTime;
            archive & networkTime;
        }
    };

    struct SmbTimestamps {
        SmbTimestamps() {}
        SmbTimestamps(const TimePoint &inAccessTime, const TimePoint &inModifyTime, const TimePoint &inChangeTime,
                        const TimePoint &inBirthTime) :
                        accessTime(inAccessTime), modifyTime(inModifyTime), changeTime(inChangeTime),
                        birthTime(inBirthTime) {}
        TimePoint accessTime = TimePoint{};
        TimePoint modifyTime = TimePoint{};
        TimePoint changeTime = TimePoint{};
        TimePoint birthTime = TimePoint{};

        bool operator<(const SmbTimestamps &tp) const {
            if (accessTime == tp.accessTime)
                if (modifyTime == tp.modifyTime)
                        return changeTime < tp.changeTime;
                else
                    return modifyTime < tp.modifyTime;
            else
                return accessTime < tp.accessTime;
        };

        bool operator==(const SmbTimestamps &tp) const {
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

    // TODO: make FileSnapshot global abstract
    struct SmbFileSnapshot {
        SmbFileSnapshot() {}
        SmbFileSnapshot(const std::vector<Fragment> &inFragments, const std::set<std::string> &inClientIPs, bool inReadOperation)
                        : fragments(inFragments), clientIPs(inClientIPs), readOperation(inReadOperation) {}
        std::vector<Fragment> fragments;
        std::set<std::string> clientIPs;
        bool readOperation = false;
        std::set<SmbTimeTriple> accesses;

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & fragments;
            archive & clientIPs;
            archive & accesses;
            archive & readOperation;
        }
    };

    class SmbFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<SmbFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        bool showFile() override;

        void initializeFilePtr(const smb::SmbContextPtr &smbContext, const std::string &filePath,
                                const smb::FileMetaDataPtr &metaData);

        void addTimestampToList(const TimePoint &networkTime, const smb::FileMetaDataPtr &metaData) {
            if (metaData->lastAccessTime != 0 && metaData->lastWriteTime != 0 && metaData->changeTime != 0) {
                fsTimestamps[networkTime] = SmbTimestamps(
                                                smb::winFiletimeToTimePoint(metaData->lastAccessTime),
                                                smb::winFiletimeToTimePoint(metaData->lastWriteTime),
                                                smb::winFiletimeToTimePoint(metaData->changeTime),
                                                smb::winFiletimeToTimePoint(metaData->creationTime)
                                                );
            }
        };

        bool processFileForDirLayout() { return (!flags.test(pcapfs::flags::IS_METADATA) || config.showMetadata); };

        void deduplicateVersions(const Index &idx);

        std::vector<std::shared_ptr<SmbFile>> const constructSmbVersionFiles(); // TODO: move this to serverfile?
        bool constructSnapshotFile();

        void saveCurrentTimestamps(const TimePoint& currNetworkTimestamp, const std::chrono::seconds &skew, bool writeOperation);

        void addAsNewFileVersion() {
            fileVersions[timestampsOfCurrVersion] = SmbFileSnapshot(fragments, clientIPs, isCurrentlyReadOperation);
        }

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        bool isCurrentlyReadOperation = false;

    private:
        std::shared_ptr<SmbFile> clone() { return std::make_shared<SmbFile>(*this); };

        Bytes const getContentForFragments(const Index &idx, const std::vector<Fragment> &inFragments);

        std::map<TimePoint, SmbTimestamps> const getAllTimestamps();

        // map network time - fs time
        std::map<TimePoint, SmbTimestamps> fsTimestamps; // TODO: also add that to serverfile.h?

        std::map<TimePoint, SmbTimestamps> hybridTimestamps; // TODO: also add that to serverfile.h?

        std::map<SmbTimeTriple, SmbFileSnapshot> fileVersions; // TODO: also add that to serverfile.h?

        // only needed for parsing
        SmbTimeTriple timestampsOfCurrVersion;

        bool donotDisplay = false;

    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<SmbFile> SmbFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
