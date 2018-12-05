#include "pcapng.h"

#include "../exceptions.h"
#include "../filefactory.h"


pcapfs::PcapNgFile::PcapNgFile(){
    setFiletype("pcapng");
    flags.set(pcapfs::flags::IS_REAL_FILE);
    reader = nullptr;
}


pcapfs::PcapNgFile::~PcapNgFile() {
    closeReader();
}

bool pcapfs::PcapNgFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcapng", pcapfs::PcapNgFile::create);
