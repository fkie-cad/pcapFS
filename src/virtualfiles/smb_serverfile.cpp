#include "smb_serverfile.h"
#include "smb/smb_utils.h"


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


void pcapfs::SmbServerFile::initializeFilePtr(const std::shared_ptr<smb::SmbContext> &smbContext, const std::string &inFilename,
                                                uint64_t lastAccessTime, uint64_t inFilesize, uint32_t treeId) {
    Fragment fragment;
    fragment.id = smbContext->offsetFile->getIdInIndex();
    fragment.start = 0;
    fragment.length = 0;
    fragments.push_back(fragment);
    setFilename(inFilename);
    setTimestamp(smb::winFiletimeToTimePoint(lastAccessTime));
    setProperty("protocol", "smb");
    setFiletype("smbserverfile");
    setOffsetType(smbContext->offsetFile->getFiletype());
    setProperty("srcIP", smbContext->offsetFile->getProperty("srcIP"));
    setProperty("dstIP", smbContext->offsetFile->getProperty("dstIP"));
    setProperty("srcPort", smbContext->offsetFile->getProperty("srcPort"));
    setProperty("dstPort", smbContext->offsetFile->getProperty("dstPort"));
    if (smbContext->treeNames.find(treeId) != smbContext->treeNames.end())
        setProperty("smbTree", smbContext->treeNames.at(treeId));
    flags.set(pcapfs::flags::PROCESSED);
    setFilesizeRaw(inFilesize);
    setFilesizeProcessed(inFilesize);
}


bool pcapfs::SmbServerFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbserverfile", pcapfs::SmbServerFile::create, pcapfs::SmbServerFile::parse);
