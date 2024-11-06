#include "smb.h"
#include "smb/smb_utils.h"
#include "smb/smb_manager.h"
#include "../index.h"

#include <numeric>
#include <boost/serialization/set.hpp>


bool pcapfs::SmbFile::showFile() {
    if (donotDisplay ||
        (flags.test(pcapfs::flags::IS_METADATA) && !config.showMetadata) ||
        (!config.showAll && flags.test(pcapfs::flags::PARSED)))
        return false;
    else {
        if (config.noFsTimestamps &&
            ((config.snip.first != ZERO_TIME_POINT && accessTime < config.snip.first) ||
            (config.snip.second != ZERO_TIME_POINT && accessTime > config.snip.second))){
            return false;
        } else
            return true;
    }
}


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
    fileVersions.emplace(timestampsOfCurrVersion, SmbFileSnapshot(fragments, clientIPs, isCurrentlyReadOperation));

    // nothing to deduplicate
    if (fileVersions.size() <= 1)
        return;

    LOG_TRACE << "deduplicating file versions of " << filename;
    std::vector<std::map<SmbTimePair, SmbFileSnapshot>::iterator> toBeErased;
    auto currVersion = fileVersions.begin();
    while (currVersion != fileVersions.end()) {
        auto cmpVersion = std::next(currVersion);
        if (cmpVersion == fileVersions.end()) {
            break;
        }

        const Bytes a = this->getContentForFragments(idx, currVersion->second.fragments);
        const Bytes b = this->getContentForFragments(idx, cmpVersion->second.fragments);
        if (a == b) {
            LOG_TRACE << "found duplicate versions";
            // copy clientIPs to version that is kept
            for (const auto &ip: currVersion->second.clientIPs) {
                cmpVersion->second.clientIPs.insert(ip);
            }

            toBeErased.push_back(currVersion);
        } else {
            LOG_TRACE << "versions are different";
        }
        currVersion++;
    }

    for (const auto &pos: toBeErased)
        fileVersions.erase(pos);
}

void pcapfs::SmbFile::setNearestTimestamp() {
    if (timestampList.empty()) {
        // should not happen
        accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
    } else {
        // take newest timestamp (or nearest timestamp if snip option is set)
        auto target = timestampList.rbegin();
        if (config.snip.second != ZERO_TIME_POINT) {
            while (target != timestampList.rend() && target->first > config.snip.second)
                ++target;

            if (target == timestampList.rend() || target->first < config.snip.first) {
                // smb file won't be displayed because it has no matching timestamp in snip interval
                donotDisplay = true;
                return;
            }
        }

        if (config.noFsTimestamps) {
            accessTime = changeTime = modifyTime = target->first;
        } else {
            accessTime = target->second.accessTime;
            changeTime = target->second.changeTime;
            modifyTime = target->second.modifyTime;
        }
    }
}


std::vector<std::shared_ptr<pcapfs::SmbFile>> const pcapfs::SmbFile::constructSmbVersionFiles() {
    std::vector<SmbFilePtr> resultVector;

    if (fileVersions.size() <= 1) {
        setNearestTimestamp();
        return resultVector;
    }

    // TODO: this has to be changed! -> probably just remove config.noFsTimestamps from if clause
    auto timestampPos = timestampList.rbegin();
    if (config.snip.second != ZERO_TIME_POINT && fileVersions.begin()->first.networkTime > config.snip.second &&
        (timestampPos = std::find_if(timestampList.rbegin(), timestampList.rend(),
                                    [](const auto &entry){ return (entry.first <= config.snip.second) && (entry.first >= config.snip.first); }
                                    )) != timestampList.rend()) {
        // special case: options noFsTimestamps + snip are set and the oldest file version is newer then the upper bound of snip.
        // when in addition the file has a saved timestamp that fits into the interval specified by snip, we set the corresponding
        // timestamp and display the file as metadata file
        // This corresponds to a scenario in which it is already known, that the file exists (e.g. through query directory) before something is
        // read/written from/to the file and snip specifies an early time interval before the read/write
        accessTime = timestampPos->first;
        changeTime = timestampPos->first;
        modifyTime = timestampPos->first;
        filesizeRaw = filesizeProcessed = 0;
        fragments.clear();
        flags.set(flags::IS_METADATA);
        return resultVector;
    }

    size_t i = 0;
    auto currVersion = fileVersions.begin();
    while (currVersion != fileVersions.end()) {
        if ((config.snip.first != ZERO_TIME_POINT && currVersion->first.networkTime < config.snip.first) ||
            (config.snip.second != ZERO_TIME_POINT && currVersion->first.networkTime > config.snip.second)) {
            // file version does not beong to snip interval
            currVersion++;
            i++;
            continue;
        }
        SmbFilePtr newFile(this->clone());
        newFile->setFilename(filename + "@" + std::to_string(i));

        if (config.noFsTimestamps) {
            newFile->setAccessTime(currVersion->first.networkTime);
            newFile->setChangeTime(currVersion->first.networkTime);
            newFile->setModifyTime(currVersion->first.networkTime);
        } else {
            bool smbTimestampsSet = false;
            SmbTimestamps targetTimestamps;
            for(const auto &entry: timestampList) {
                if (entry.second.accessTime <= currVersion->first.fsTime &&
                    entry.second.changeTime <= currVersion->first.fsTime &&
                    entry.second.modifyTime <= currVersion->first.fsTime) {
                    targetTimestamps = entry.second;
                    smbTimestampsSet = true;
                }
            }
            if (smbTimestampsSet) {
                newFile->setAccessTime(targetTimestamps.accessTime);
                newFile->setChangeTime(targetTimestamps.changeTime);
                newFile->setModifyTime(targetTimestamps.modifyTime);
            } else {
                // no matching timestamps found
                newFile->setAccessTime(ZERO_TIME_POINT);
                newFile->setChangeTime(ZERO_TIME_POINT);
                newFile->setModifyTime(ZERO_TIME_POINT);
            }
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
    if (resultVector.empty() && (config.snip.first != ZERO_TIME_POINT || config.snip.second != ZERO_TIME_POINT)) {
        setNearestTimestamp();
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
    timestampList[smbContext->currentTimestamp] = SmbTimestamps(accessTime, modifyTime, changeTime, birthTime);
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


void pcapfs::SmbFile::saveCurrentTimestamps(const TimePoint& currNetworkTimestamp, const std::chrono::seconds &skew, bool writeOperation) {
    // first, we get the nearest filesystem timestamp
    // when having a read operation read, the corresponding network timestamp from the timestampList has to be older
    // than currNetworkTimestamp and for write, it has to be newer

    // TODO: for hbrid mode: we need to add the the possible time skew between network and fs time
    // this only has impact when the negotiate protocol response was recorded
    //const TimePoint referenceTimestamp = currNetworkTimestamp + skew;

    // TODO:
    // if fs timestamp mode: set timestamps for write operations always to zero
    // (and don't show the corresponding versions if --snapshot)
    // der referenceTimestamp für den hybrid timestamp mode -> mache aus SmbTimePair SmbTimeTriple (bzw. abtrahiere das in astrakter Manager-Klasse)

    TimePoint nearestFsTimestamp;
    auto entry = timestampList.begin();
    if (currNetworkTimestamp >= entry->first) {

        while (entry != timestampList.end() && entry->first <= currNetworkTimestamp)
            ++entry;

        if ((!writeOperation && entry != timestampList.begin()) || (writeOperation && entry == timestampList.end()))
            --entry;

        nearestFsTimestamp = std::max({entry->second.accessTime, entry->second.changeTime, entry->second.modifyTime});
    }

    timestampsOfCurrVersion = SmbTimePair(nearestFsTimestamp, currNetworkTimestamp);
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
