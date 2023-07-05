#include "pcap.h"

#include "../exceptions.h"
#include "../filefactory.h"


pcapfs::PcapFile::PcapFile(){
    setFiletype("pcap");
    flags.set(pcapfs::flags::IS_REAL_FILE);
    reader = nullptr;
}


pcapfs::PcapFile::~PcapFile() {
    closeReader();
}

size_t pcapfs::PcapFile::getOffsetFromLastBlock(size_t i) {
    return i == 0 ? 24 : 16;
}


bool pcapfs::PcapFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcap", pcapfs::PcapFile::create);
