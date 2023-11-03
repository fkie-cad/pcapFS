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
    const unsigned char DSB_MAGIC[4] = {0x0A, 0x00, 0x00, 0x00};
    const unsigned char TLSKEYLOG_SECRET_TYPE[4] = {0x4B, 0x53, 0x4C, 0x54};

    class PcapNgFile : public CaptureFile {
    public:
        PcapNgFile();

        ~PcapNgFile() override;

        static FilePtr create() { return std::make_shared<PcapNgFile>(); };

        size_t getOffsetFromLastBlock(size_t i) override;
        std::shared_ptr<pcpp::IFileReaderDevice> getReader() override;
        void parsePacketOffsets(Index &idx);

    private:
        const std::vector<FilePtr> extractEmbeddedKeyFiles(const Bytes blockBody);

        std::vector<size_t> packetOffsets;
        static bool registeredAtFactory;

    };

    typedef std::shared_ptr<PcapNgFile> PcapNgPtr;

}

#endif //PCAPFS_CAPTURE_FILES_PCAPNG_H
