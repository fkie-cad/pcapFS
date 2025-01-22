#ifndef PCAPFS_VIRTUAL_FILES_FTP_CONTROL_H
#define PCAPFS_VIRTUAL_FILES_FTP_CONTROL_H

#include "../commontypes.h"
#include "virtualfile.h"
#include "../file.h"
#include "ftp/ftp_utils.h"


namespace pcapfs {

    class FtpControlFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<FtpControlFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    protected:
        using Command = std::pair<std::string, std::vector<std::string>>;

        static bool registeredAtFactory;

        static const std::string DEFAULT_DATA_PORT;
        static const std::string COMMAND_PORT;
        static const uint8_t RESPONSE_CODE_LN;
        static const std::pair<uint8_t, uint8_t> ASCII_INT_RANGE;
        static const std::string DATA_DIRECTION_PREFIX_IN;
        static const std::string DATA_DIRECTION_PREFIX_OUT;
        static const uint8_t DATA_DIRECTION_PREFIX_LN;

        static std::string const constructDirPathString(const std::vector<std::string> &params, const std::string &dstIP, const std::string &cwd);

        static void fillGlobalProperties(std::shared_ptr<FtpControlFile> &result, FilePtr &filePtr);

        static bool isClientCommand(FilePtr filePtr);

        static bool isServerResponse(FilePtr filePtr);

        static bool charIsInt(char c);

        static void
        parseResult(std::shared_ptr<pcapfs::FtpControlFile> result, pcapfs::FilePtr filePtr, size_t i);

        static void parseUSERCredentials(std::shared_ptr<FtpControlFile> &result, size_t i, FilePtr &filePtr,
                                         std::shared_ptr<FtpControlFile> &credentials);

        static void parsePASSCredentials(FilePtr &filePtr, std::shared_ptr<FtpControlFile> &result,
                                         std::shared_ptr<FtpControlFile> &credentials, size_t i);

        static void
        parseCredentials(std::shared_ptr<pcapfs::FtpControlFile> result, pcapfs::FilePtr filePtr, size_t i);

        static size_t calculateSize(pcapfs::FilePtr filePtr, size_t numElements, size_t i, const uint64_t &offset);

        static bool isLastElement(size_t numElements, size_t i);

        static Fragment parseOffset(pcapfs::FilePtr &filePtr, const uint64_t &offset, size_t size);

        static bool isResponse(char *raw_data);

        static uint8_t handleResponse(std::shared_ptr<FtpControlFile> &result, size_t size,
                                      char *raw_data, TimePoint timestamp);

        static FtpResponse parseResponse(char *raw_data, size_t size, TimePoint timestamp);

        static void
        handleResponseTypes(const FtpResponse &response, std::shared_ptr<pcapfs::FtpControlFile> &result);

        static std::string const parsePassivePort(std::string message);

        static std::string const  parseExtendedPassivePort(std::string message);

        static uint8_t
        handleCommand(const std::shared_ptr<pcapfs::FtpControlFile> &result, const pcapfs::FilePtr &filePtr,
                      size_t i, size_t size);

        static FtpResponse
        getCommandResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements, pcapfs::Bytes &data);

        static TimePoint
        getTimestampAfterResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements,
                                  const pcapfs::FtpResponse &response);

        static pcapfs::FtpControlFile::Command parseCommand(char *raw_data, size_t size);

        static void
        handleCommandTypes(std::shared_ptr<FtpControlFile> result, const pcapfs::FilePtr &filePtr,
                            const Command &cmd, const FtpResponse &response, const TimeSlot &time_slot);


        Bytes readRawData(const pcapfs::Index &idx, const Fragment &fragment) const;

        uint8_t insertDirectionPrefixes(pcapfs::Bytes &rawData, size_t i) const;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_FTP_CONTROL_H
