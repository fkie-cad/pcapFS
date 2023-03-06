#ifndef PCAPFS_CAPTURE_FILES_CAPTUREFILE_H
#define PCAPFS_CAPTURE_FILES_CAPTUREFILE_H

#include <fstream>

#include <pcapplusplus/PcapFileDevice.h>

#include "../file.h"
#include "../index.h"


namespace pcapfs {

    class CaptureFile : public File {

    public:
        CaptureFile() = default;

        ~CaptureFile();

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        bool showFile() override { return false; };

        static std::vector<FilePtr> createFromPaths(pcapfs::Paths pcapPaths);

        std::shared_ptr<pcpp::IFileReaderDevice> getReader();

        void closeReader();

        virtual size_t getPacketHeaderLen() = 0;

        virtual size_t getGlobalHeaderLen() = 0;

    protected:
        std::ifstream fileHandle;
        std::shared_ptr<pcpp::IFileReaderDevice> reader;

    };
}

#endif //PCAPFS_CAPTURE_FILES_CAPTUREFILE_H
