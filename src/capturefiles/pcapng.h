#ifndef PCAPFS_CAPTURE_FILES_PCAPNG_H
#define PCAPFS_CAPTURE_FILES_PCAPNG_H

#include "../commontypes.h"
#include "capturefile.h"


namespace pcapfs {

    class PcapNgFile : public CaptureFile {
    public:
        PcapNgFile();

        ~PcapNgFile() override;

        static FilePtr create() { return std::make_shared<PcapNgFile>(); };

        size_t getPacketHeaderLen() override { return 0; };

        size_t getGlobalHeaderLen() override { return 0; };

    private:
        static bool registeredAtFactory;

    };

    typedef std::shared_ptr<PcapNgFile> PcapNgPtr;

}

#endif //PCAPFS_CAPTURE_FILES_PCAPNG_H
