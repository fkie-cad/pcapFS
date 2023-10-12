#include "smb_serverfile.h"


std::vector<pcapfs::FilePtr> pcapfs::SmbServerFile::parse(FilePtr filePtr, Index &idx) {
    (void)filePtr;
    (void)idx;
    return std::vector<pcapfs::FilePtr>(0);
}


size_t pcapfs::SmbServerFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    (void)startOffset;
    (void)length;
    (void)idx;
    (void)buf;
    return 0;
}


bool pcapfs::SmbServerFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbserverfile", pcapfs::SmbServerFile::create, pcapfs::SmbServerFile::parse);