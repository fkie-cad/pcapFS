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

        size_t getPacketHeaderLen() override { return 16; };

        size_t getGlobalHeaderLen() override { return 24; };

    private:
        static bool registeredAtFactory;

    };

    typedef std::shared_ptr<PcapFile> PcapPtr;

}

#endif //PCAPFS_CAPTURE_FILES_PCAP_H
