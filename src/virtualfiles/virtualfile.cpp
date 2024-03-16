#include "virtualfile.h"

#include "../dirlayout.h"
#include "../logging.h"

//TODO: create constructor

std::string pcapfs::VirtualFile::getFilename() {
    std::string temp;
    if (filetype == "cobaltstrike" || filetype == "cs_uploadedfile" || filetype == "smbserverfile")
        return filename;

    if (fragments.empty()) {
        LOG_ERROR << "found no fragment in file " << filename << " with index "
                  << filetype << std::to_string(this->getIdInIndex());
        exit(1);
    }

    if (filetype == "tcp" || filetype == "udp") {
        temp = std::to_string(fragments.at(0).id) + "-" + std::to_string(firstPacketNumber);
    } else {
        temp = std::to_string(fragments.at(0).id) + "-" + std::to_string(fragments.at(0).start);
    }

    if (flags.test(pcapfs::flags::MISSING_DATA)) {
        temp = temp + "_" + "0PAD";
    }

    //assuming 30 chars for extensions
    if (filename.size() < 225) {
        if (!filename.empty()) {
            temp = temp + "_" + filename;
        }
    }

    if (flags.test(pcapfs::flags::IS_METADATA)) {
        if (filetype == "tls") {
            temp += ".pem";
        } else {
            temp += ".meta";
        }
    }

    return temp;
}


bool pcapfs::VirtualFile::showFile() {
    if (flags.test(pcapfs::flags::IS_METADATA) && !config.showMetadata) {
        return false;
    }
    if (!config.showAll && flags.test(pcapfs::flags::PARSED)) {
        return false;
    }
    return true;
}


void pcapfs::VirtualFile::serialize(boost::archive::text_oarchive &archive) {
    File::serialize(archive);
    archive << offsetType;
    archive << firstPacketNumber;
    archive << fragments;
}


void pcapfs::VirtualFile::deserialize(boost::archive::text_iarchive &archive) {
    File::deserialize(archive);
    archive >> offsetType;
    archive >> firstPacketNumber;
    archive >> fragments;
}
