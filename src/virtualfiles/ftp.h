#ifndef PCAPFS_VIRTUAL_FILES_FTP_H
#define PCAPFS_VIRTUAL_FILES_FTP_H

#include "serverfile.h"
#include "ftp/ftp_utils.h"

namespace pcapfs {

    struct FtpFileTransmissionData {
        std::string transmission_file;
        std::string transmission_type;
        TimeSlot time_slot;
    };


    class FtpFile : public ServerFile {
    public:
        static FilePtr create() { return std::make_shared<FtpFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void fillGlobalProperties(const FilePtr &filePtr);
        void parseResult(const FilePtr &filePtr);
        void handleAllFilesToRoot(const std::string &filePath, const ServerFileContextPtr &context);

        void addFsTimestamp(const TimePoint &networkTime, const TimePoint &fsTime) { fsTimestamps[networkTime] = fsTime; };

        std::vector<FilePtr> const constructVersionFiles() override;
        bool constructSnapshotFile() override;

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

    protected:
        static bool registeredAtFactory;

        static std::vector<FtpFileTransmissionData> getTransmissionDataForPort(pcapfs::FilePtr &filePtr);

        static FtpFileTransmissionData getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                                            const std::vector<FtpFileTransmissionData> &transmission_data);

        static bool connectionBreaksInTimeSlot(TimePoint break_time, const TimeSlot &time_slot);

        static void handleMlsd(const FilePtr &filePtr, const std::string &filePath);

        std::map<TimePoint, TimePoint> fsTimestamps;
    };

    typedef std::shared_ptr<FtpFile> FtpFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_FTP_H
