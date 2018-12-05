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


bool pcapfs::PcapFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcap", pcapfs::PcapFile::create);
