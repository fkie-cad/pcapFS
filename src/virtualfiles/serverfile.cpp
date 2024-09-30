#include "serverfile.h"
#include <boost/serialization/set.hpp>

std::vector<std::shared_ptr<pcapfs::ServerFile>> pcapfs::ServerFile::getAllParentDirs() {
    std::vector<std::shared_ptr<ServerFile>> result;
    if (!parentDir)
        return result;

    std::shared_ptr<ServerFile> currParentDir = std::static_pointer_cast<pcapfs::ServerFile>(parentDir);
    result.insert(result.begin(), currParentDir);
    while (currParentDir->getParentDir()) {
        currParentDir = std::static_pointer_cast<pcapfs::ServerFile>(currParentDir->getParentDir());
        result.insert(result.begin(), currParentDir);
    }
    return result;
}


void pcapfs::ServerFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << accessTime;
    archive << modifyTime;
    archive << changeTime;
    archive << birthTime;
    archive << (isDirectory ? 1 : 0);
    archive << parentDirId;
    archive << clientIPs;
}


void pcapfs::ServerFile::deserialize(boost::archive::text_iarchive &archive) {
    int i = 0;
    VirtualFile::deserialize(archive);
    archive >> accessTime;
    archive >> modifyTime;
    archive >> changeTime;
    archive >> birthTime;
    archive >> i;
    isDirectory = i ? true : false;
    archive >> parentDirId;
    archive >> clientIPs;
}
