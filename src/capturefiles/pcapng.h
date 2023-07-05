#ifndef PCAPFS_CAPTURE_FILES_PCAPNG_H
#define PCAPFS_CAPTURE_FILES_PCAPNG_H

#include "../commontypes.h"
#include "capturefile.h"


namespace pcapfs {

    struct PcapNgBlockHdr {
        unsigned char blockType[4];
        unsigned char blockLength[4];
    };

    const unsigned char SHB_MAGIC[4] = {0x0A, 0x0D, 0x0D, 0x0A};
    const unsigned char EPB_MAGIC[4] = {0x06, 0x00, 0x00, 0x00};
    const unsigned char SPB_MAGIC[4] = {0x03, 0x00, 0x00, 0x00};

    class PcapNgFile : public CaptureFile {
    public:
        PcapNgFile();

        ~PcapNgFile() override;

        static FilePtr create() { return std::make_shared<PcapNgFile>(); };

        size_t getOffsetFromLastBlock(size_t i) override;
        void parsePacketOffsets();

    private:
        static bool registeredAtFactory;

    protected:
        std::vector<size_t> packetOffsets;

    };

    typedef std::shared_ptr<PcapNgFile> PcapNgPtr;

}

#endif //PCAPFS_CAPTURE_FILES_PCAPNG_H
