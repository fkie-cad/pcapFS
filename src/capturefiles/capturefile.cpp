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
        if (boost::filesystem::extension(pcapName) == ".pcap") {
            std::shared_ptr<PcapFile> pcapFile = std::make_shared<pcapfs::PcapFile>();
            pcapFile->setFilename(pcapName.string());
            pcapFile->setFilesizeRaw(boost::filesystem::file_size(pcapName));
            pcapFile->setFiletype("pcap");
            result.emplace_back(pcapFile);
        } else if (boost::filesystem::extension(pcapName) == ".pcapng") {
            std::shared_ptr<PcapNgFile> pcapngFile = std::make_shared<pcapfs::PcapNgFile>();
            pcapngFile->setFilename(pcapName.string());
            pcapngFile->setFilesizeRaw(boost::filesystem::file_size(pcapName));
            pcapngFile->setFiletype("pcapng");
            pcapngFile->parsePacketOffsets(idx);
            result.emplace_back(pcapngFile);
        }
    }
    return result;
}


std::shared_ptr<pcpp::IFileReaderDevice> pcapfs::CaptureFile::getReader() {
    if (reader == nullptr) {
        reader = std::make_shared<pcpp::PcapFileReaderDevice>(filename.c_str());
    }

    if (!reader->open()) {
        LOG_ERROR << "Error opening the PCAP file '" << filename << "'";
        throw pcapfs::PcapFsException("Error opening the PCAP file '" + filename + "'");
    }
    return reader;
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
