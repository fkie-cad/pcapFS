#ifndef PCAPFS_VIRTUAL_FILES_SMB_H
#define PCAPFS_VIRTUAL_FILES_SMB_H

#include "serverfile.h"
#include "../filefactory.h"
#include "smb/smb_structs.h"

//#include <boost/serialization/set.hpp>


namespace pcapfs {

    struct SmbTimestamps {
        SmbTimestamps() {}
        SmbTimestamps(const TimePoint &inAccessTime, const TimePoint &inModifyTime, const TimePoint &inChangeTime, const TimePoint &inBirthTime) :
                        accessTime(inAccessTime), modifyTime(inModifyTime), changeTime(inChangeTime), birthTime(inBirthTime) {}
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

        /*template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive << boost::serialization::make_binary_object(&accessTime, sizeof(accessTime));
            archive << boost::serialization::make_binary_object(&modifyTime, sizeof(modifyTime));
            archive << boost::serialization::make_binary_object(&changeTime, sizeof(changeTime));
            archive << boost::serialization::make_binary_object(&birthTime, sizeof(birthTime));
        }

        template<class Archive>
        void deserialize(Archive &archive, const unsigned int) {
            archive >> boost::serialization::make_binary_object(&accessTime, sizeof(accessTime));
            archive >> boost::serialization::make_binary_object(&modifyTime, sizeof(modifyTime));
            archive >> boost::serialization::make_binary_object(&changeTime, sizeof(changeTime));
            archive >> boost::serialization::make_binary_object(&birthTime, sizeof(birthTime));
        }*/
    };

    struct SmbFileSnapshot {
        SmbFileSnapshot() {}
        SmbFileSnapshot(const std::vector<Fragment> &inFragments, const std::set<std::string> &inClientIPs) : fragments(inFragments), clientIPs(inClientIPs) {}
        std::vector<Fragment> fragments;
        std::set<std::string> clientIPs;

        /*template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive << fragments;
            archive << clientIPs;
        }

        template<class Archive>
        void deserialize(Archive &archive, const unsigned int) {
            archive >> fragments;
            archive >> clientIPs;
        }*/
    };

    class SmbFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<SmbFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void initializeFilePtr(const smb::SmbContextPtr &smbContext, const std::string &filePath,
                                const smb::FileMetaDataPtr &metaData);

        void updateTimestampList() { timestampList.insert(SmbTimestamps(accessTime, modifyTime, changeTime, birthTime)); };
        void addTimestampToList(const SmbTimestamps &tp) { timestampList.insert(tp); };

        void deduplicateVersions(const Index &idx);

        std::set<SmbTimestamps> const getTimestampList() { return timestampList; };

        std::shared_ptr<SmbFile> clone() { return std::make_shared<SmbFile>(*this); };

        std::vector<std::shared_ptr<SmbFile>> const constructSmbVersionFiles();

        //void serialize(boost::archive::text_oarchive &archive) override;
        //void deserialize(boost::archive::text_iarchive &archive) override;

        std::map<TimePoint, SmbFileSnapshot> fileVersions;

    private:
        Bytes const getContentForFragments(const Index &idx, const std::vector<Fragment> &inFragments);

        std::set<SmbTimestamps> timestampList;
    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<SmbFile> SmbFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
