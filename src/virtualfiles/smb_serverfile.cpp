#include "smb_serverfile.h"
#include "smb/smb_utils.h"
#include "smb/smb_manager.h"


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


void pcapfs::SmbServerFile::initializeFilePtr(const std::shared_ptr<smb::SmbContext> &smbContext, const std::string &filePath,
                                                const smb::FileMetaDataPtr &metaData) {
    Fragment fragment;
    fragment.id = smbContext->offsetFile->getIdInIndex();
    fragment.start = 0;
    fragment.length = 0;
    fragments.push_back(fragment);

    accessTime = smb::winFiletimeToTimePoint(metaData->lastAccessTime);
    modifyTime = smb::winFiletimeToTimePoint(metaData->lastWriteTime);
    changeTime = smb::winFiletimeToTimePoint(metaData->changeTime);
    birthTime = smb::winFiletimeToTimePoint(metaData->creationTime);
    isDirectory = metaData->isDirectory;

    const size_t backslashPos = filePath.rfind("\\");
    if (filePath != "\\" && backslashPos != std::string::npos) {
        setFilename(std::string(filePath.begin()+backslashPos+1, filePath.end()));
        LOG_TRACE << "filename set: " << std::string(filePath.begin()+backslashPos+1, filePath.end());
        const std::string remainder(filePath.begin(), filePath.begin()+backslashPos);

        // TODO: outsource this part fully into getAsParentDirFile (i.e., when remainder is empty, take tree name into account
        // and set this as parent dir)
        if(!remainder.empty()) {
            LOG_TRACE << "detected subdir(s)";
            LOG_TRACE << "remainder: " << remainder;
            parentDir = smb::SmbManager::getInstance().getAsParentDirFile(remainder, smbContext);
        } else {
            // root directory has nullptr as parentDir
            parentDir = nullptr;
        }
    } else {
        // TODO: set tree name as parent dir
        // consider the case that we already handle a part of the tree name path (which might start with \ or not)
        // => at some point, parentDir must be set to nullptr
        setFilename(filePath);
        parentDir = nullptr;
    }

    setTimestamp(accessTime);
    setProperty("protocol", "smb");
    setFiletype("smbserverfile");
    setOffsetType(smbContext->offsetFile->getFiletype());
    setProperty("srcIP", smbContext->offsetFile->getProperty("srcIP"));
    setProperty("dstIP", smbContext->offsetFile->getProperty("dstIP"));
    setProperty("srcPort", smbContext->offsetFile->getProperty("srcPort"));
    setProperty("dstPort", smbContext->offsetFile->getProperty("dstPort"));
    setProperty("smbTree", smb::SmbManager::getInstance().constructTreeString(smbContext->serverEndpoint, smbContext->currentTreeId));
    flags.set(pcapfs::flags::PROCESSED);
    setFilesizeRaw(metaData->filesize);
    setFilesizeProcessed(metaData->filesize);
}


bool pcapfs::SmbServerFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smbserverfile", pcapfs::SmbServerFile::create, pcapfs::SmbServerFile::parse);
