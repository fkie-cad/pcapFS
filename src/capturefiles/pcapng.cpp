#include "pcapng.h"

#include "../exceptions.h"
#include "../filefactory.h"
#include "../keyfiles/sslkey.h"

#include <sstream>


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

void pcapfs::PcapNgFile::parsePacketOffsets(Index &idx) {
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
        else if (memcmp(currBlock.blockType, DSB_MAGIC, 4) == 0) {
            // we have a Decryption Secrets Block and extract the embedded TLS keys
            // (can be injected into pcaps by: editcap --inject-secrets tls,keys.txt in.pcap out-dsb.pcapng)
            const Bytes blockBody(&fileContent[currPos + 8], &fileContent[currPos + currBlockLength - 4]);
            std::vector<FilePtr> keyFiles = extractEmbeddedKeyFiles(blockBody);
            idx.insertKeyCandidates(keyFiles);
            offsetToLastPacketBlock += currBlockLength;
        }
        else
            offsetToLastPacketBlock += currBlockLength;

        currPos += currBlockLength;
    }
}


const std::vector<pcapfs::FilePtr> pcapfs::PcapNgFile::extractEmbeddedKeyFiles(const Bytes blockBody) {
    std::vector<FilePtr> result(0);
    if (memcmp(blockBody.data(), TLSKEYLOG_SECRET_TYPE, 4) != 0) {
        LOG_INFO << "Found Decryption Secrets Block with unsupported Secrets Type. We skip that.";
        return result;
    }

    const uint32_t secretsLength = *((uint32_t*) &blockBody[4]);
    if (secretsLength > blockBody.size() - 8) {
        LOG_WARNING << "Decryption Secrets Block of pcapng file has invalid Secret Length";
        return result;
    }

    LOG_TRACE << "extract key file(s) embedded in a pcapng file";
    std::stringstream secretsData(std::string(&blockBody[8], &blockBody[8 + secretsLength]));
    std::string line;
    while (std::getline(secretsData, line, '\n')){
        std::shared_ptr<SSLKeyFile> keyFile = SSLKeyFile::extractKeyContent(line);
        if (keyFile)
            result.push_back(keyFile);
    }

    return result;
}


bool pcapfs::PcapNgFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("pcapng", pcapfs::PcapNgFile::create);
