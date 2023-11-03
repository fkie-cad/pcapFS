#include "capturefile.h"

#include "pcap.h"
#include "pcapng.h"
#include "../commontypes.h"
#include "../logging.h"
#include "../exceptions.h"



pcapfs::CaptureFile::CaptureFile(){
    flags.set(pcapfs::flags::IS_REAL_FILE);
    reader = nullptr;
}


size_t pcapfs::CaptureFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: sanitize inputs with filesize
    if (!fileHandle.is_open()) {
        LOG_TRACE << "setting file handle to " << idx.getCurrentWorkingDirectory() << "/" << filename;
        Path path(filename);
        if (path.is_absolute()) {
            fileHandle.open(filename, std::ios_base::in | std::ios_base::binary);
        } else {
            fileHandle.open(idx.getCurrentWorkingDirectory() + "/" + filename,
                            std::ios_base::in | std::ios_base::binary);
        }

        if (fileHandle.fail()) {
            LOG_ERROR << "File " << filename << " could not be opened";
            throw PcapFsException("File " + filename + " could not be opened");
        }
    }

    fileHandle.seekg(startOffset);
    if (startOffset + length > filesizeRaw) {
        fileHandle.read(buf, filesizeRaw - startOffset);
        LOG_TRACE << "read from " << filename << " from " << startOffset << " with length "
                  << (filesizeRaw - startOffset);
        return filesizeRaw - startOffset;
    } else {
        fileHandle.read(buf, length);
        LOG_TRACE << "read from " << filename << " from " << startOffset << " with length " << length;

        return length;
    }
}


std::vector<pcapfs::FilePtr> pcapfs::CaptureFile::createFromPaths(pcapfs::Paths pcapPaths, Index &idx) {
    std::vector<pcapfs::FilePtr> result;
    for (const auto &pcapName: pcapPaths) {
        uint8_t captureFileType = determineCaptureFileType(pcapName, idx);
        switch (captureFileType) {
            case CaptureFileType::PCAP_FILE:
                {
                    std::shared_ptr<PcapFile> pcapFile = std::make_shared<pcapfs::PcapFile>();
                    pcapFile->setFilename(pcapName.string());
                    pcapFile->setFilesizeRaw(boost::filesystem::file_size(pcapName));
                    pcapFile->setFiletype("pcap");
                    result.emplace_back(pcapFile);
                }
                break;

            case CaptureFileType::PCAPNG_FILE:
                {
                    std::shared_ptr<PcapNgFile> pcapngFile = std::make_shared<pcapfs::PcapNgFile>();
                    pcapngFile->setFilename(pcapName.string());
                    pcapngFile->setFilesizeRaw(boost::filesystem::file_size(pcapName));
                    pcapngFile->setFiletype("pcapng");
                    pcapngFile->parsePacketOffsets(idx);
                    result.emplace_back(pcapngFile);
                }
                break;

            case CaptureFileType::UNSUPPORTED_FILE:
                LOG_WARNING << "file " << pcapName << " has an unsupported file type";
                break;
        }
    }
    return result;
}


uint8_t pcapfs::CaptureFile::determineCaptureFileType(const pcapfs::Path &pcapName, const Index &idx) {
    char magicBuf[4];
    memset(magicBuf, 0, 4);
    std::ifstream ifs;
    LOG_TRACE << "determine file type of " << pcapName;

    if (pcapName.is_absolute())
        ifs.open(pcapName.string(), std::ios_base::in | std::ios_base::binary);
    else
        ifs.open(idx.getCurrentWorkingDirectory() + "/" + pcapName.string(), std::ios_base::in | std::ios_base::binary);

    if (ifs.fail())
        throw PcapFsException("File " + pcapName.string() + " could not be opened");

    ifs.seekg(0);
    ifs.read(magicBuf, 4);
    ifs.close();
    if (memcmp(magicBuf, PCAP_MAGIC_1, 4) == 0 || memcmp(magicBuf, PCAP_MAGIC_2, 4) == 0)
        return CaptureFileType::PCAP_FILE;
    else if (memcmp(magicBuf, SHB_MAGIC, 4) == 0)
        return CaptureFileType::PCAPNG_FILE;
    else
        return CaptureFileType::UNSUPPORTED_FILE;
}


void pcapfs::CaptureFile::closeReader() {
    if (reader != nullptr && reader->isOpened()) {
        reader->close();
    }
}


pcapfs::CaptureFile::~CaptureFile() {
    if (fileHandle.is_open()) {
        fileHandle.close();
    }
}
