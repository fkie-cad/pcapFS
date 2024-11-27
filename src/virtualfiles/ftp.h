#ifndef PCAPFS_VIRTUAL_FILES_FTP_H
#define PCAPFS_VIRTUAL_FILES_FTP_H

#include "serverfile.h"

namespace pcapfs {

    struct FileTransmissionData {
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

    protected:
        static bool registeredAtFactory;

        static std::vector<FileTransmissionData> getTransmissionDataForPort(pcapfs::FilePtr &filePtr);

        static FileTransmissionData getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                                            const std::vector<FileTransmissionData> &transmission_data);

        static bool connectionBreaksInTimeSlot(TimePoint break_time, const TimeSlot &time_slot);

        static void handleMlsdFiles(const FilePtr &filePtr, const std::string &filePath);
    };

    typedef std::shared_ptr<FtpFile> FtpFilePtr;
}

#endif //PCAPFS_VIRTUAL_FILES_FTP_H
