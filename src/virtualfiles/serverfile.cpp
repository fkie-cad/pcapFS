#include "serverfile.h"

void pcapfs::ServerFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << boost::serialization::make_binary_object(&accessTime, sizeof(accessTime));
    archive << boost::serialization::make_binary_object(&modifyTime, sizeof(modifyTime));
    archive << boost::serialization::make_binary_object(&changeTime, sizeof(changeTime));
    archive << boost::serialization::make_binary_object(&birthTime, sizeof(birthTime));
    archive << (isDirectory ? 1 : 0);
    archive << parentDirId;
}


void pcapfs::ServerFile::deserialize(boost::archive::text_iarchive &archive) {
    int i = 0;
    VirtualFile::deserialize(archive);
    archive >> boost::serialization::make_binary_object(&accessTime, sizeof(accessTime));
    archive >> boost::serialization::make_binary_object(&modifyTime, sizeof(modifyTime));
    archive >> boost::serialization::make_binary_object(&changeTime, sizeof(changeTime));
    archive >> boost::serialization::make_binary_object(&birthTime, sizeof(birthTime));
    archive >> i;
    isDirectory = i ? true : false;
    archive >> parentDirId;
}
