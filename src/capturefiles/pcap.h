#ifndef PCAPFS_CAPTURE_FILES_PCAP_H
#define PCAPFS_CAPTURE_FILES_PCAP_H

#include "capturefile.h"
#include "../commontypes.h"


namespace pcapfs {

    class PcapFile : public CaptureFile {
    public:
        PcapFile();

        ~PcapFile() override;

        static FilePtr create() { return std::make_shared<PcapFile>(); };

        size_t getOffsetFromLastBlock(size_t i) override;

        std::shared_ptr<pcpp::IFileReaderDevice> getReader() override;

    private:
        static bool registeredAtFactory;

    };

    typedef std::shared_ptr<PcapFile> PcapPtr;

}

#endif //PCAPFS_CAPTURE_FILES_PCAP_H
