#include "smb.h"
#include "smb/smb_utils.h"
#include "smb/smb_manager.h"
#include "../index.h"

#include <numeric>
#include <boost/serialization/set.hpp>


std::vector<pcapfs::FilePtr> pcapfs::SmbFile::parse(FilePtr filePtr, Index &idx) {
    (void)filePtr;
    (void)idx;
    return std::vector<pcapfs::FilePtr>(0);
}


size_t pcapfs::SmbFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    if (fragments.size() == 0 || (fragments.size() == 1 && fragments.at(0).length == 0)) {
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


pcapfs::Bytes const pcapfs::SmbFile::getContentForFragments(const Index &idx, const std::vector<Fragment> &inFragments) {
    Bytes result(0);
    for (Fragment frag: inFragments) {
        if (frag.length == 0)
            continue;
        Bytes rawData(frag.length);
        FilePtr filePtr = idx.get({offsetType, frag.id});
        filePtr->read(frag.start, frag.length, idx, reinterpret_cast<char *>(rawData.data()));
        result.insert(result.end(), rawData.begin(), rawData.end());
    }
    return result;
}


void pcapfs::SmbFile::deduplicateVersions(const Index &idx) {
    if (fragments.size() == 0 || (fragments.size() == 1 && fragments.at(0).length == 0))
        return;

    // add current saved fragments as newest version
    fileVersions.emplace(timestamp, SmbFileSnapshot(fragments, clientIPs, isCurrentlyReadOperation));

    if (fileVersions.size() <= 1)
        return;

    std::vector<std::map<TimePoint, SmbFileSnapshot>::iterator> toBeErased;
    auto currVersion = fileVersions.begin();
    while (currVersion != fileVersions.end()) {
        auto cmpVersion = std::next(currVersion);
        if (cmpVersion == fileVersions.end())
            break;
        const Bytes a = this->getContentForFragments(idx, currVersion->second.fragments);
        const Bytes b = this->getContentForFragments(idx, cmpVersion->second.fragments);
        if (a == b) {
            LOG_TRACE << "found duplicate versions";
            // advance back to the position where to add the clientIPs of the duplicate version
            // (this can be multiple steps away when we have multiple consecutive duplicates)
            auto posToInsertClientIPs = currVersion;
            while (std::find(toBeErased.begin(), toBeErased.end(), posToInsertClientIPs) != toBeErased.end())
                posToInsertClientIPs--;

            for (const auto &ip: cmpVersion->second.clientIPs)
                posToInsertClientIPs->second.clientIPs.insert(ip);

            toBeErased.push_back(cmpVersion);
        } else {
            LOG_TRACE << "versions are different";
        }
        currVersion++;
    }

    for (const auto &pos: toBeErased)
        fileVersions.erase(pos);
}


std::vector<std::shared_ptr<pcapfs::SmbFile>> const pcapfs::SmbFile::constructSmbVersionFiles() {
    std::vector<SmbFilePtr> resultVector;
    if (fileVersions.size() <= 1)
        return resultVector;

    size_t i = 0;
    auto currVersion = fileVersions.begin();
    while (currVersion != fileVersions.end()) {
        SmbFilePtr newFile(this->clone());
        newFile->setFilename(filename + "@" + std::to_string(i));

        // TODO make timestamp list to a lookup map so that i don't have to run through all time stamps every time?
        bool smbTimestampsSet = false;
        SmbTimestamps targetTimestamps;
        for(const auto &smbTimestamps: timestampList) {
            if (smbTimestamps.accessTime <= currVersion->first && currVersion->first <= currVersion->first && smbTimestamps.modifyTime <= currVersion->first) {
                targetTimestamps = smbTimestamps;
                smbTimestampsSet = true;
            }
        }
        if (smbTimestampsSet) {
            newFile->setAccessTime(targetTimestamps.accessTime);
            newFile->setChangeTime(targetTimestamps.changeTime);
            newFile->setModifyTime(targetTimestamps.modifyTime);
        } else {
            // no matching timestamps found
            newFile->setAccessTime(currVersion->first);
            newFile->setChangeTime(currVersion->first);
            newFile->setModifyTime(currVersion->first);
        }

        newFile->fragments = currVersion->second.fragments;
        newFile->setClientIPs(currVersion->second.clientIPs);
        const size_t calculatedFilesize = std::accumulate(newFile->fragments.begin(), newFile->fragments.end(), 0,
                                                                        [](size_t counter, const auto &frag){ return counter + frag.length; });
        newFile->setFilesizeRaw(calculatedFilesize);
        newFile->setFilesizeProcessed(calculatedFilesize);
        // we need to change IdInIndex s.t. it becomes a uniquely indexable file
        newFile->setIdInIndex(smb::SmbManager::getInstance().getNewId());

        resultVector.push_back(newFile);
        currVersion++;
        i++;
    }

    return resultVector;
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
    timestampList.insert(SmbTimestamps(accessTime, modifyTime, changeTime, birthTime));
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


void pcapfs::SmbFile::serialize(boost::archive::text_oarchive &archive) {
    ServerFile::serialize(archive);
    archive << timestampList;
    archive << fileVersions;
}


void pcapfs::SmbFile::deserialize(boost::archive::text_iarchive &archive) {
    ServerFile::deserialize(archive);
    archive >> timestampList;
    archive >> fileVersions;
}


bool pcapfs::SmbFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smb", pcapfs::SmbFile::create, pcapfs::SmbFile::parse);
