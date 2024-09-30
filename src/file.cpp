#include <chrono>

#include "file.h"

#include "logging.h"
#include "exceptions.h"


std::string pcapfs::File::getProperty(const std::string &property) {
    return properties[property];
}

void pcapfs::File::setProperty(const std::string &a, const std::string &b) {
    properties[a] = b;
}

void pcapfs::File::fillBuffer(const Index &idx) {

    if(filesizeProcessed == 0 || !flags.test(pcapfs::flags::PROCESSED)) {
        LOG_TRACE << "current buffer size: " << buffer.size();
        buffer.resize(filesizeRaw);
        read(0, filesizeRaw, idx, (char *) buffer.data());
        LOG_TRACE << "new filesizeRaw: " << filesizeRaw;
    } else {
        LOG_TRACE << "current buffer size: " << buffer.size();
        buffer.resize(filesizeProcessed);
        read(0, filesizeProcessed, idx, (char *) buffer.data());
        LOG_TRACE << "new filesizeProcessed: " << filesizeProcessed;
    }
}


pcapfs::Bytes pcapfs::File::getBuffer() {
    if (buffer.empty()) {
        LOG_ERROR << "Reading empty buffer of file " << filename;
        throw PcapFsException("Reading empty buffer of file " + filename);
    } else {
        return buffer;
    }
}


void pcapfs::File::clearBuffer() {
    buffer.clear();
}


uint64_t pcapfs::File::getFilesizeProcessed() {
    if (flags.test(pcapfs::flags::PROCESSED)) {
        return filesizeProcessed;
    } else {
        return filesizeRaw;
    }
}


bool pcapfs::File::meetsDecodeMapCriteria(const std::string &file) {
    for (const auto &entries : config.getDecodeMapFor(file)) {
        if (std::any_of(entries.begin(), entries.end(),
                        [this](const auto &it){ return this->getProperty(it.first) != it.second; })) {
            continue;
        } else {
            return true;
        }
    }
    return false;
}

std::string pcapfs::File::to_string() {
    std::stringstream ss;
    std::stringstream connectionBreaksOutputStream;

    if(!this->connectionBreaks.empty()) {
        connectionBreaksOutputStream << "\n";

        for(size_t i=0; i<this->connectionBreaks.size(); i++) {
            connectionBreaksOutputStream << "    ";
            connectionBreaksOutputStream << this->connectionBreaks.at(i).first << "\n";
        }

    } else {
        connectionBreaksOutputStream << "<none>";
    }

    ss << "File(\n"
        << "  filetype: " << this->getFiletype() << "\n"
        << "  filename: " << this->getFilename() << "\n"
        << "  filesizeRaw: " << this->getFilesizeRaw() << "\n"
        << "  filesizeProcessed: " << this->getFilesizeProcessed() << "\n"
        << "  connection breaks: " << connectionBreaksOutputStream.str() << "\n"
        //<< "  buffer: " << this->getBuffer().data() << "\n"
        << ")";

    std::string ret = ss.str();

    return ret;
}

void pcapfs::File::serialize(boost::archive::text_oarchive &archive) {
    //uint16_t
    archive << filetype;
    //std::string
    archive << filename;
    //time_point
    archive << timestamp;
    //uint64_t
    archive << filesizeRaw;
    //uint64_t
    archive << filesizeProcessed;
    //uint64_t
    archive << idInIndex;
    //std::map<std::string, std::string>
    archive << properties;
    //std::bitset
    archive << flags;
}


void pcapfs::File::deserialize(boost::archive::text_iarchive &archive) {
    //file type is handled before
    //std::string
    archive >> filename;
    //time_point
    archive >> timestamp;
    //uint64_t
    archive >> filesizeRaw;
    //uint64_t
    archive >> filesizeProcessed;
    //uint64_t
    archive >> idInIndex;
    //std::map<std::string, std::string>
    archive >> properties;
    //std::bitset
    archive >> flags;
}

pcapfs::options::PcapFsOptions pcapfs::File::config = pcapfs::options::PcapFsOptions{};

//TODO: destructor!
