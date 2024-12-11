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

        bool showFile() override;

        void initializeFilePtr(const smb::SmbContextPtr &smbContext, const std::string &filePath,
                                const smb::FileMetaDataPtr &metaData);

        void addTimestampToList(const TimePoint &networkTime, const smb::FileMetaDataPtr &metaData) {
            if (metaData->lastAccessTime != 0 && metaData->lastWriteTime != 0 && metaData->changeTime != 0) {
                fsTimestamps[networkTime] = ServerFileTimestamps(
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
            fileVersions[timestampsOfCurrVersion] = ServerFileVersion(fragments, clientIPs, isCurrentlyReadOperation);
        }

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        bool isCurrentlyReadOperation = false;

    private:
        std::shared_ptr<SmbFile> clone() { return std::make_shared<SmbFile>(*this); };

        Bytes const getContentForFragments(const Index &idx, const std::vector<Fragment> &inFragments);

        std::map<TimePoint, ServerFileTimestamps> const getAllTimestamps();

        // map network time - fs time
        std::map<TimePoint, ServerFileTimestamps> fsTimestamps; // TODO: also add that to serverfile.h?

        std::map<TimePoint, ServerFileTimestamps> hybridTimestamps; // TODO: also add that to serverfile.h?

        std::map<TimeTriple, ServerFileVersion> fileVersions; // TODO: also add that to serverfile.h?

        // only needed for parsing
        TimeTriple timestampsOfCurrVersion;

        bool donotDisplay = false;

    protected:
        static bool registeredAtFactory;
    };

    typedef std::shared_ptr<SmbFile> SmbFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_SMB_H
