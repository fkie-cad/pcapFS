#include "smb.h"
#include "smb/smb_utils.h"
#include "smb/smb_manager.h"
#include "../index.h"


std::vector<pcapfs::FilePtr> pcapfs::SmbFile::parse(FilePtr filePtr, Index &idx) {
    (void)filePtr;
    (void)idx;
    return std::vector<pcapfs::FilePtr>(0);
}


size_t pcapfs::SmbFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    if (fragments.size() == 1 && fragments.at(0).length == 0) {
        // file is empty and only consists of dummy fragment
        return 0;
    }

    Bytes totalContent(0);
    for (Fragment fragment: fragments) {
        Bytes rawData(fragment.length);
        FilePtr filePtr = idx.get({offsetType, fragment.id});
        filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
        totalContent.insert(totalContent.end(), rawData.begin(), rawData.end());
    }
    memcpy(buf, totalContent.data() + startOffset, length);
    return std::min(totalContent.size() - startOffset, length);
}


void pcapfs::SmbFile::initializeFilePtr(const smb::SmbContextPtr &smbContext, const std::string &filePath,
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

    LOG_DEBUG << "SMB: building up cascade of parent dir files for " << filePath;
    const size_t backslashPos = filePath.rfind("\\");
    if (filePath != "\\" && backslashPos != std::string::npos) {
        setFilename(std::string(filePath.begin()+backslashPos+1, filePath.end()));
        LOG_DEBUG << "filename set: " << std::string(filePath.begin()+backslashPos+1, filePath.end());
        const std::string remainder(filePath.begin(), filePath.begin()+backslashPos);

        if(!remainder.empty() && remainder != "\\") {
            LOG_DEBUG << "detected subdir(s)";
            LOG_DEBUG << "remainder: " << remainder;
            parentDir = smb::SmbManager::getInstance().getAsParentDirFile(remainder, smbContext);
        } else {
            // root directory has nullptr as parentDir
            parentDir = nullptr;
        }
    } else {
        setFilename(filePath);
        parentDir = nullptr;
    }

    setTimestamp(smbContext->currentTimestamp);
    setProperty("protocol", "smb");
    setFiletype("smb");
    setOffsetType(smbContext->offsetFile->getFiletype());
    setProperty("srcIP", smbContext->offsetFile->getProperty("srcIP"));
    setProperty("dstIP", smbContext->offsetFile->getProperty("dstIP"));
    setProperty("srcPort", smbContext->offsetFile->getProperty("srcPort"));
    setProperty("dstPort", smbContext->offsetFile->getProperty("dstPort"));
    clientIPs.insert(smbContext->clientIP);
    flags.set(pcapfs::flags::IS_METADATA);
    flags.set(pcapfs::flags::PROCESSED);
    setFilesizeRaw(0);
    setFilesizeProcessed(0);
    setIdInIndex(smb::SmbManager::getInstance().getNewId());
    parentDirId = parentDir ? parentDir->getIdInIndex() : (uint64_t)-1;
}


bool pcapfs::SmbFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smb", pcapfs::SmbFile::create, pcapfs::SmbFile::parse);
