#ifndef PCAPFS_VIRTUAL_FILES_FTP_H
#define PCAPFS_VIRTUAL_FILES_FTP_H

#include "../commontypes.h"
#include "virtualfile.h"
#include "../file.h"
#include "ftp/ftp_port_bridge.h"


namespace pcapfs {

    class FtpFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<FtpFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    protected:
        static bool registeredAtFactory;

        static std::vector<pcapfs::FileTransmissionData> getTransmissionDataForPort(pcapfs::FilePtr &filePtr);

        static size_t calculateSize(pcapfs::FilePtr filePtr, size_t numElements, size_t i, uint64_t &offset);

        static void parseResult(std::shared_ptr<pcapfs::FtpFile> result, pcapfs::FilePtr filePtr, size_t i);

        static FileTransmissionData getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                                            const std::vector<pcapfs::FileTransmissionData> &transmission_data);

        static bool connectionBreaksInTimeSlot(TimePoint break_time, const TimeSlot &time_slot);

        static std::string constructFileName(const FileTransmissionData &d);

        static void fillGlobalProperties(std::shared_ptr<FtpFile> &result, FilePtr &filePtr);

        static SimpleOffset parseOffset(pcapfs::FilePtr &filePtr, const uint64_t &offset, size_t size);
    };
}

#endif //PCAPFS_VIRTUAL_FILES_FTP_H
