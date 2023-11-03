#ifndef PCAPFS_CAPTURE_FILES_CAPTUREFILE_H
#define PCAPFS_CAPTURE_FILES_CAPTUREFILE_H

#include <fstream>

#include <pcapplusplus/PcapFileDevice.h>

#include "../file.h"
#include "../index.h"


namespace pcapfs {

    enum CaptureFileType : uint8_t {
        PCAP_FILE = 0,
        PCAPNG_FILE = 1,
        UNSUPPORTED_FILE = 3
    };

    const unsigned char SHB_MAGIC[4] = {0x0A, 0x0D, 0x0D, 0x0A};
    const unsigned char PCAP_MAGIC_1[4] = {0xD4, 0xC3, 0xB2, 0xA1};
    const unsigned char PCAP_MAGIC_2[4] = {0x4D, 0x3C, 0xB2, 0xA1};

    class CaptureFile : public File {

    public:
        CaptureFile();

        ~CaptureFile();

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        bool showFile() override { return false; };

        static std::vector<FilePtr> createFromPaths(pcapfs::Paths pcapPaths, Index &idx);

        virtual std::shared_ptr<pcpp::IFileReaderDevice> getReader() = 0;

        void closeReader();

        virtual size_t getOffsetFromLastBlock(size_t i) = 0;

    protected:
        std::ifstream fileHandle;
        std::shared_ptr<pcpp::IFileReaderDevice> reader;

    private:
        static uint8_t determineCaptureFileType(const pcapfs::Path &pcapName, const Index &idx);

    };
}

#endif //PCAPFS_CAPTURE_FILES_CAPTUREFILE_H
