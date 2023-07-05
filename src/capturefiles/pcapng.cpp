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


size_t pcapfs::PcapNgFile::getOffsetFromLastBlock(size_t i) {
    return packetOffsets[i];
}

void pcapfs::PcapNgFile::parsePacketOffsets() {
    if (!fileHandle.is_open()) {
        Path path(filename);
        if (path.is_absolute()) {
            fileHandle.open(filename, std::ios_base::in | std::ios_base::binary);
        } else {
            fileHandle.open(boost::filesystem::current_path().string() + "/" + filename,
                            std::ios_base::in | std::ios_base::binary);
        }

        if (fileHandle.fail())
            throw PcapFsException("File " + filename + " could not be opened");
    }

    packetOffsets.push_back(0);

    Bytes fileContent(filesizeRaw);
    PcapNgBlockHdr currBlock;
    size_t currPos = 0;
    uint32_t currBlockLength, offsetToLastPacketBlock = 0;

    fileHandle.read((char*) fileContent.data(), filesizeRaw);
    if (memcmp(fileContent.data(), SHB_MAGIC, 4) != 0)
        throw pcapfs::PcapFsException("pcapng file " + filename + " is invalid");

    while (currPos < filesizeRaw) {
        memcpy(&currBlock, &fileContent[currPos], 8);
        currBlockLength = *((uint32_t*) currBlock.blockLength);
        if (currPos + currBlockLength > filesizeRaw)
            throw pcapfs::PcapFsException("packet block in pcapng file " + filename + " has invalid size");

        if (memcmp(currBlock.blockType, EPB_MAGIC, 4) == 0) {
            packetOffsets.push_back(offsetToLastPacketBlock + 28);
            offsetToLastPacketBlock = currBlockLength - 28;
        }
        else if (memcmp(currBlock.blockType, SPB_MAGIC, 4) == 0) {
            packetOffsets.push_back(offsetToLastPacketBlock + 12);
            offsetToLastPacketBlock = currBlockLength - 12;
        }
        else
            offsetToLastPacketBlock += currBlockLength;

        currPos += currBlockLength;
    }
}


bool pcapfs::PcapNgFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcapng", pcapfs::PcapNgFile::create);
