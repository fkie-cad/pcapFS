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


std::shared_ptr<pcpp::IFileReaderDevice> pcapfs::PcapFile::getReader() {
    if (reader == nullptr) {
        reader = std::make_shared<pcpp::PcapFileReaderDevice>(filename.c_str());
    }

    if (!reader->open()) {
        LOG_ERROR << "Error opening the PCAP file '" << filename << "'";
        throw pcapfs::PcapFsException("Error opening the PCAP file '" + filename + "'");
    }
    return reader;
}


bool pcapfs::PcapFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcap", pcapfs::PcapFile::create);
