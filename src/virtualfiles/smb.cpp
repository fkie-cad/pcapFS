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
        if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK &&
            ((config.snip.first != ZERO_TIME_POINT && accessTime < config.snip.first) ||
            (config.snip.second != ZERO_TIME_POINT && accessTime >= config.snip.second))){
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


std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps> const pcapfs::SmbFile::getAllTimestamps() {
    // returns union of hybridTimestamps and fsTimestamps
    std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps> result = hybridTimestamps;
    for (const auto &entry: fsTimestamps) {
        result[entry.first] = entry.second;
    }
    return result;
}


void pcapfs::SmbFile::deduplicateVersions(const Index &idx) {
    if (fragments.size() == 0 || (fragments.size() == 1 && fragments.at(0).length == 0))
        return;

    // add current saved fragments as newest version
    fileVersions.emplace(timestampsOfCurrVersion, ServerFileVersion(fragments, clientIPs, isCurrentlyReadOperation));

    // nothing to deduplicate
    if (fileVersions.size() <= 1)
        return;

    LOG_DEBUG << "deduplicating file versions of " << filename;
    std::vector<std::map<TimeTriple, ServerFileVersion>::iterator> toBeErased;
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
            // copy clientIPs and time points of file accesses to version that is kept
            for (const auto &ip: currVersion->second.clientIPs) {
                cmpVersion->second.clientIPs.insert(ip);
            }
            cmpVersion->second.accesses = currVersion->second.accesses;
            cmpVersion->second.accesses.insert(currVersion->first);

            // we deduplicate a possible pair of duplicate versions with
            // (write,read) (read,write) to a single version with read
            if (currVersion->second.readOperation)
                cmpVersion->second.readOperation = true;

            toBeErased.push_back(currVersion);
        } else {
            LOG_TRACE << "versions are different";
        }
        currVersion++;
    }

    for (const auto &pos: toBeErased)
        fileVersions.erase(pos);
}


bool pcapfs::SmbFile::constructSnapshotFile() {

    const auto referenceTimestamps = config.timestampMode == pcapfs::options::TimestampMode::FS ? fsTimestamps : getAllTimestamps();
    std::reverse_iterator<std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps>::const_iterator> targetTimestampPos;
    TimePoint upperBoundTimestamp = config.snapshot;
    std::reverse_iterator<std::set<TimeTriple>::const_iterator> tmpTimestampPos;
    bool foundMatchingTimestamps = false;

    // first, we select the file version that matches the snapshot time
    auto currVersion = fileVersions.begin();
    if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
        // advance to file version corresponding to the specified snapshot time
        while (currVersion != fileVersions.end() && currVersion->first.networkTime <= config.snapshot) {

            if (config.snip.second != ZERO_TIME_POINT && currVersion->first.networkTime >= config.snip.second) {
                // a snip interval is specified and we are outside of it

                    if (std::find_if(currVersion->second.accesses.crbegin(), currVersion->second.accesses.crend(),
                                        [](const auto &access){
                                            return  (config.snip.first != ZERO_TIME_POINT && access.networkTime >= config.snip.first) ||
                                                    (config.snip.second != ZERO_TIME_POINT && access.networkTime < config.snip.second);
                                        }) != currVersion->second.accesses.crend()
                        ) {
                        // the network timestamp of the file version is outside of snip interval but the version has a saved access time
                        // which fits inside
                        upperBoundTimestamp = config.snip.second;
                    } else {
                        // outside of snip interval and no saved access time is inside snip interval
                        break;
                    }
            }

            currVersion++;
        }
        // select suitable timstamp
       if ((targetTimestampPos = std::find_if(referenceTimestamps.rbegin(), referenceTimestamps.rend(),
                                                    [upperBoundTimestamp](const auto &entry){ return entry.first <= upperBoundTimestamp &&
                                                                            ((config.snip.first == ZERO_TIME_POINT || entry.first >= config.snip.first) &&
                                                                            (config.snip.second == ZERO_TIME_POINT || entry.first < config.snip.second)); }
                                                )) != referenceTimestamps.rend()) {
            foundMatchingTimestamps = true;
        }

    } else {
        if (config.timestampMode == pcapfs::options::TimestampMode::HYBRID) {
            while (currVersion != fileVersions.end() && currVersion->first.hybridTime <= config.snapshot) {

                if (config.snip.second != ZERO_TIME_POINT && currVersion->first.networkTime >= config.snip.second) {
                    // snip interval specified and we are outside of it

                        if ((tmpTimestampPos = std::find_if(currVersion->second.accesses.crbegin(), currVersion->second.accesses.crend(),
                                                [](const auto &access){
                                                    return  (config.snip.first == ZERO_TIME_POINT && access.networkTime >= config.snip.first) ||
                                                            (config.snip.second == ZERO_TIME_POINT && access.networkTime < config.snip.second);
                                                })) != currVersion->second.accesses.crend()
                            ) {
                            // the network timestamp of the file version is outside of snip interval but the version has a saved access time
                            // which fits inside -> take this access time
                            upperBoundTimestamp = tmpTimestampPos->hybridTime;
                        } else {
                            // outside of snip interval and no saved access time is inside snip interval
                            break;
                        }
                }

                currVersion++;
            }

            // select suitable timestamp
            auto tmpHybridTimestampPos = std::find_if(hybridTimestamps.rbegin(), hybridTimestamps.rend(),
                                                    [upperBoundTimestamp](const auto &entry){ return entry.second.accessTime <= upperBoundTimestamp &&
                                                                            entry.second.changeTime <= upperBoundTimestamp &&
                                                                            entry.second.modifyTime <= upperBoundTimestamp &&
                                                                            ((config.snip.first == ZERO_TIME_POINT || entry.first >= config.snip.first) &&
                                                                            (config.snip.second == ZERO_TIME_POINT || entry.first < config.snip.second)); }
                                            );

            if ((targetTimestampPos = std::find_if(referenceTimestamps.rbegin(), referenceTimestamps.rend(),
                                                    [upperBoundTimestamp](const auto &entry){ return entry.second.accessTime <= upperBoundTimestamp &&
                                                                            entry.second.changeTime <= upperBoundTimestamp &&
                                                                            entry.second.modifyTime <= upperBoundTimestamp &&
                                                                            ((config.snip.first == ZERO_TIME_POINT || entry.first >= config.snip.first) &&
                                                                            (config.snip.second == ZERO_TIME_POINT || entry.first < config.snip.second)); }
                                                )) != referenceTimestamps.rend()) {
                foundMatchingTimestamps = true;
                if (tmpHybridTimestampPos != hybridTimestamps.rend() && (tmpHybridTimestampPos->second.accessTime > targetTimestampPos->second.accessTime ||
                                                                        tmpHybridTimestampPos->second.changeTime > targetTimestampPos->second.changeTime ||
                                                                        tmpHybridTimestampPos->second.modifyTime > targetTimestampPos->second.modifyTime)) {
                    // because referenceTimestamps is a mix of fs and hybrid timestamps, it can be the case that, when iterating over referenceTimestamps,
                    // the selected targetTimestampPos is not optimal (i.e., later coming timestamps are nearer to snapshot time) because the networkTime of
                    // targetTimestampPos is higher and thus the suboptimal timestamps are seen first.
                    // When this if condition is reached, we have a hybrid timestamp which is nearer to the snapshot time
                    targetTimestampPos = tmpHybridTimestampPos;
                }
            }

        } else {
            // fs mode
            while (currVersion != fileVersions.end() && currVersion->first.fsTime <= config.snapshot &&
                    (std::next(currVersion) != fileVersions.end() || currVersion->second.readOperation)) {
                // the second condition covers the case that the last file version is from a write operation (-> the corresponding fsTime is 0)
                // then, we don't want to go further
                if (config.snip.second != ZERO_TIME_POINT && currVersion->first.networkTime >= config.snip.second) {
                    // snip interval specified and we are outside of it

                    if ((tmpTimestampPos = std::find_if(currVersion->second.accesses.crbegin(), currVersion->second.accesses.crend(),
                                            [](const auto &access){
                                                return  (config.snip.first != ZERO_TIME_POINT && access.networkTime >= config.snip.first) ||
                                                        (config.snip.second != ZERO_TIME_POINT && access.networkTime < config.snip.second);
                                            })) != currVersion->second.accesses.crend()
                        ) {
                        // the network timestamp of the file version is outside of snip interval but the version has a saved access time
                        // which fits inside -> take this access time
                        if (tmpTimestampPos->fsTime != ZERO_TIME_POINT) {
                            upperBoundTimestamp = tmpTimestampPos->fsTime;
                        }
                    } else {
                        // outside of snip interval and no saved access time is inside snip interval
                        break;
                    }
                }

                currVersion++;
            }

            // select suitable timestamp
            if ((targetTimestampPos = std::find_if(referenceTimestamps.rbegin(), referenceTimestamps.rend(),
                                                    [upperBoundTimestamp](const auto &entry){ return entry.second.accessTime <= upperBoundTimestamp &&
                                                                            entry.second.changeTime <= upperBoundTimestamp &&
                                                                            entry.second.modifyTime <= upperBoundTimestamp &&
                                                                            ((config.snip.first == ZERO_TIME_POINT || entry.first >= config.snip.first) &&
                                                                            (config.snip.second == ZERO_TIME_POINT || entry.first < config.snip.second)); }
                                                )) != referenceTimestamps.rend()) {
                foundMatchingTimestamps = true;
            }
        }
    }


    if (currVersion == fileVersions.begin()) {
        // at this point, the timestamp for the oldest file version is newer than the requested snapshot time
        // or no file versions are saved
        if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {

            if (foundMatchingTimestamps) {
                LOG_DEBUG << "found no matching file version for " << filename << " but a matching timestamp";
                accessTime = changeTime = modifyTime = targetTimestampPos->first;

                if (fileVersions.size() > 0 &&
                    std::any_of(currVersion->second.accesses.cbegin(), currVersion->second.accesses.cend(),
                                [](const auto &access){ return access.networkTime <= config.snapshot; }
                    )) {
                    // file was accessed with recorded read/write before snapshot time but due to deduplication
                    // the network timestamp of the file version is newer than snapshot time
                    LOG_DEBUG << "matching file version for " << filename << " was one further due to deduplication";
                    fragments = currVersion->second.fragments;
                    clientIPs = currVersion->second.clientIPs;
                    filesizeRaw = filesizeProcessed = std::accumulate(fragments.begin(), fragments.end(), 0,
                                                                [](size_t counter, const auto &frag){ return counter + frag.length; });
                    return true;
                }

                if (!flags.test(pcapfs::flags::IS_METADATA)) {
                    fragments.clear(),
                    filesizeRaw = filesizeProcessed = 0;
                    flags.set(pcapfs::flags::IS_METADATA);
                }
            } else {
                LOG_DEBUG << "didn't find matching timestamp for " << filename;
                return false;
            }
        } else {
            if (foundMatchingTimestamps) {

                if (fileVersions.size() > 0 &&
                    (((config.timestampMode == pcapfs::options::TimestampMode::HYBRID &&
                    std::any_of(currVersion->second.accesses.cbegin(), currVersion->second.accesses.cend(),
                                [](const auto &access){ return access.hybridTime <= config.snapshot; })
                    ) ||
                    (config.timestampMode == pcapfs::options::TimestampMode::FS &&
                    std::any_of(currVersion->second.accesses.cbegin(), currVersion->second.accesses.cend(),
                                [](const auto &access){ return access.fsTime != ZERO_TIME_POINT && access.fsTime <= config.snapshot; })
                    )) ||
                    (targetTimestampPos->second.changeTime <= config.snapshot && currVersion->second.readOperation))) {
                    // display the content of the smb file although snapshot time is newer than fs/hybrid time of oldest file version
                    // (fs/hybrid time of file version is always the max of access/modify/change time.)
                    // With this, we cover the case that the oldest file version was accessed after the snapshot
                    // but the changeTime is is older than the snapshot.
                    // Then, we can be sure that the file was not modified and can display it.

                    // Another case we cover here is that the file was accessed with recorded read/write before snapshot time
                    // but due to deduplication the fs/hybrid timestamp of the file version is newer than snapshot time
                    LOG_DEBUG << "matching file version for " << filename << " was one further due to deduplication";
                    fragments = currVersion->second.fragments;
                    clientIPs = currVersion->second.clientIPs;
                    filesizeRaw = filesizeProcessed = std::accumulate(fragments.begin(), fragments.end(), 0,
                                                                [](size_t counter, const auto &frag){ return counter + frag.length; });
                } else {
                    // we end up here in two cases:
                    // 1. we have a metadata file
                    // 2. the file has content (recorded reads/writes) and a timestamp that matches the snapshot time
                    // but the first recorded file operation is write and happens after the specified snapshot time
                    // (then we know that the file existed but we don't know its content at that time)
                    fragments.clear(),
                    filesizeRaw = filesizeProcessed = 0;
                    flags.set(pcapfs::flags::IS_METADATA);
                }
                accessTime = targetTimestampPos->second.accessTime;
                changeTime = targetTimestampPos->second.changeTime;
                modifyTime = targetTimestampPos->second.modifyTime;
            } else {
                LOG_DEBUG << "didn't find matching timestamp for " << filename;
                return false;
            }
        }
    } else {
        // at this point, the file version selected according to the snapshot time is not the first file version
        // and we are one file version too far

        if (config.timestampMode == pcapfs::options::TimestampMode::FS && currVersion == fileVersions.end()) {
            currVersion--;
            if (!currVersion->second.readOperation) {
                // we have write operation for the file version of the corresponding snapshot time
                // => we don't have an exact fs timestamp for that
                // => taking solely fs timestamps into account (what we do in fs mode), we can't certainly tell
                // what the file content is at that time
                // => display as metadata file
                fragments.clear(),
                filesizeRaw = filesizeProcessed = 0;
                flags.set(pcapfs::flags::IS_METADATA);
                accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
                return true;
            }
        } else if (currVersion == fileVersions.end() ||
                    ((config.timestampMode == pcapfs::options::TimestampMode::NETWORK &&
                    std::none_of(currVersion->second.accesses.begin(), currVersion->second.accesses.end(),
                                [](const auto &ac){ return ac.networkTime <= config.snapshot; })) ||
                    (config.timestampMode == pcapfs::options::TimestampMode::HYBRID &&
                    std::none_of(currVersion->second.accesses.begin(), currVersion->second.accesses.end(),
                                [](const auto &ac){ return ac.hybridTime <= config.snapshot; })) ||
                    (config.timestampMode == pcapfs::options::TimestampMode::FS &&
                    std::none_of(currVersion->second.accesses.begin(), currVersion->second.accesses.end(),
                                [](const auto &ac){ return ac.fsTime != ZERO_TIME_POINT && ac.fsTime <= config.snapshot; }))
                    )){
            // Though the timestamp, which is saved as key of currVersion, is the first timestamp that is higher than the snapshot time,
            // it can be the case that, due to deduplication, this file version (which is originally one version too new)
            // has been accessed before the snapshot time. In this case, we don't want to decrement.
            currVersion--;
        }

        // set fragments and filesize accordingly
        fragments = currVersion->second.fragments;
        clientIPs = currVersion->second.clientIPs;
        filesizeRaw = filesizeProcessed =  std::accumulate(fragments.begin(), fragments.end(), 0,
                                                            [](size_t counter, const auto &frag){ return counter + frag.length; });

        if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
            if (foundMatchingTimestamps) {
                accessTime = changeTime = modifyTime = targetTimestampPos->first;
            } else {
                // no matching timestamps found
                LOG_DEBUG << "found matching file version for " << filename << " but no timestamp, this should not happen";
                accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
            }
        } else {
            // hybrid and fs mode
            if (foundMatchingTimestamps) {
                accessTime = targetTimestampPos->second.accessTime;
                changeTime = targetTimestampPos->second.changeTime;
                modifyTime = targetTimestampPos->second.modifyTime;
            } else {
                // no matching timestamps found
                LOG_DEBUG << "found matching file version for " << filename << " but no timestamp, this should not happen";
                accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
            }
        }
    }
    return true;
}


std::vector<std::shared_ptr<pcapfs::SmbFile>> const pcapfs::SmbFile::constructSmbVersionFiles() {
    std::vector<SmbFilePtr> resultVector;

    const auto referenceTimestamps = config.timestampMode == pcapfs::options::TimestampMode::FS ? fsTimestamps : getAllTimestamps();
    if (fileVersions.size() <= 1) {
        // metadata file, directory file or only one read/write (deduplicated)
        if (referenceTimestamps.empty() ||
            (fileVersions.size() == 1 && config.timestampMode == pcapfs::options::TimestampMode::FS &&
                !fileVersions.begin()->second.readOperation)) {
            // no timestamps saved or fs mode and the only file version is from write operation
            accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
        } else {
            // take newest timestamp (or nearest timestamp if snip option is set)
            // (snip is always w.r.t. network timestamps)
            auto target = referenceTimestamps.crbegin();
            if (config.snip.second != ZERO_TIME_POINT) {
                while (target != referenceTimestamps.crend() && target->first >= config.snip.second)
                    ++target;

                if (target == referenceTimestamps.crend() || target->first < config.snip.first) {
                    // smb file won't be displayed because it has no matching timestamp in snip interval
                    LOG_DEBUG << filename << "has no matching timestamp in snip interval";
                    donotDisplay = true;
                    return resultVector;
                }
            }
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                accessTime = changeTime = modifyTime = target->first;
            } else {
                accessTime = target->second.accessTime;
                changeTime = target->second.changeTime;
                modifyTime = target->second.modifyTime;
            }
        }
        return resultVector;
    }

    // from this point onwards, we have multiple file versions
    // => construct separate smb file for each version
    size_t i = 0;
    auto currVersion = fileVersions.begin();
    while (currVersion != fileVersions.end()) {
        if (((config.snip.first != ZERO_TIME_POINT && currVersion->first.networkTime < config.snip.first) ||
            (config.snip.second != ZERO_TIME_POINT && currVersion->first.networkTime >= config.snip.second)) &&
            std::all_of(currVersion->second.accesses.cbegin(), currVersion->second.accesses.cend(),
                            [](const auto &access){ return (config.snip.first != ZERO_TIME_POINT && access.networkTime < config.snip.first) ||
                                                            (config.snip.second != ZERO_TIME_POINT && access.networkTime >= config.snip.second); }
                        )
            ) {
            // file version does not belong to snip interval
            currVersion++;
            i++;
            continue;
        }
        SmbFilePtr newFile(this->clone());
        newFile->setFilename(filename + "@" + std::to_string(i));

        if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
            newFile->setAccessTime(currVersion->first.networkTime);
            newFile->setChangeTime(currVersion->first.networkTime);
            newFile->setModifyTime(currVersion->first.networkTime);

        } else if (config.timestampMode == pcapfs::options::TimestampMode::HYBRID || currVersion->second.readOperation) {
            const auto pos = (i == fileVersions.size() - 1) ? referenceTimestamps.crbegin() :
                                std::find_if(referenceTimestamps.crbegin(), referenceTimestamps.crend(),
                                            [currVersion](const auto &entry){ return entry.first <= currVersion->first.networkTime; });

            if (pos == referenceTimestamps.crend()) {
                newFile->setAccessTime(ZERO_TIME_POINT);
                newFile->setChangeTime(ZERO_TIME_POINT);
                newFile->setModifyTime(ZERO_TIME_POINT);
            } else {
                newFile->setAccessTime(pos->second.accessTime);
                newFile->setChangeTime(pos->second.changeTime);
                newFile->setModifyTime(pos->second.modifyTime);
            }
        } else {
            // fs mode and write operation
            newFile->setAccessTime(ZERO_TIME_POINT);
            newFile->setChangeTime(ZERO_TIME_POINT);
            newFile->setModifyTime(ZERO_TIME_POINT);
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
        // no file version fits into the specified snip interval
        // Nevertheless, it can be the case that the file has been during this interval.
        auto timestampPos = referenceTimestamps.crbegin();
        if ((timestampPos = std::find_if(referenceTimestamps.crbegin(), referenceTimestamps.crend(),
                                    [](const auto &entry){ return (entry.first < config.snip.second) && (entry.first >= config.snip.first); }
                                    )) != referenceTimestamps.crend()) {

            if (config.snip.second != ZERO_TIME_POINT && !hybridTimestamps.empty() && hybridTimestamps.begin()->first > config.snip.second) {
                // the oldest network timestamp key of the hybrid timestamps is newer than the upper bound of snip.
                // Since this network timestamp corresponds to the point in time, in which the first read/write happened,
                // we now know that the oldest read/write is newer than the upper bound of snip
                // Still, because we have timestamps that fit into the specified snip interval, we know that the file was accessed there,
                // but not with read/write
                // => we set the smb file as metadata file
                filesizeRaw = filesizeProcessed = 0;
                fragments.clear();
                flags.set(flags::IS_METADATA);
            }
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                accessTime = changeTime = modifyTime = timestampPos->first;
            } else {
                accessTime = timestampPos->second.accessTime;
                changeTime = timestampPos->second.changeTime;
                modifyTime = timestampPos->second.modifyTime;
            }
        } else {
            // no matching timestamps in snip interval
            donotDisplay = true;
        }
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

    if (metaData->lastAccessTime != 0 && metaData->lastWriteTime != 0 && metaData->changeTime != 0)
        fsTimestamps[smbContext->currentTimestamp] = ServerFileTimestamps(
                                                                    smb::winFiletimeToTimePoint(metaData->lastAccessTime),
                                                                    smb::winFiletimeToTimePoint(metaData->lastWriteTime),
                                                                    smb::winFiletimeToTimePoint(metaData->changeTime),
                                                                    smb::winFiletimeToTimePoint(metaData->creationTime)
        );

    isDirectory = metaData->isDirectory;

    LOG_DEBUG << "SMB: building up cascade of parent dir files for " << filePath;
    const size_t backslashPos = filePath.rfind("\\");
    if (filePath != "\\" && backslashPos != std::string::npos) {
        filename = std::string(filePath.begin()+backslashPos+1, filePath.end());
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
        filename = filePath;
        parentDir = nullptr;
    }

    properties["protocol"] = "smb";
    filetype = "smb";
    offsetType = smbContext->offsetFile->getFiletype();
    properties["srcIP"] = smbContext->offsetFile->getProperty("srcIP");
    properties["dstIP"] = smbContext->offsetFile->getProperty("dstIP");
    properties["srcPort"] = smbContext->offsetFile->getProperty("srcPort");
    properties["dstPort"] = smbContext->offsetFile->getProperty("dstPort");
    clientIPs.insert(smbContext->clientIP);
    filesizeRaw = filesizeProcessed = 0;
    idInIndex = smb::SmbManager::getInstance().getNewId();
    parentDirId = parentDir ? parentDir->getIdInIndex() : (uint64_t)-1;
    clientIPs.insert(smbContext->clientIP);
    flags.set(pcapfs::flags::IS_METADATA);
    flags.set(pcapfs::flags::PROCESSED);
}


void pcapfs::SmbFile::saveCurrentTimestamps(const TimePoint& currNetworkTimestamp, const std::chrono::seconds &skew, bool writeOperation) {
    // This function is called from the SMB manager during handling of read/write messages

    const TimePoint derivedFsTimestamp = currNetworkTimestamp + skew;
    const auto fsTimestampsPos = std::find_if(fsTimestamps.crbegin(), fsTimestamps.crend(),
                                            [currNetworkTimestamp](const auto &entry){ return entry.first <= currNetworkTimestamp; });

    if (fsTimestampsPos == fsTimestamps.crend()) {
        // only happens in specific edge case
        timestampsOfCurrVersion = TimeTriple(derivedFsTimestamp, ZERO_TIME_POINT, currNetworkTimestamp);
        // we don't add a hybrid timestamp in that case
    } else {
        // search latest (hybrid/fs) timestamp as reference for new hybrid timestamp
        // it can be the case that this does not correspond to the first entry <= currNetworkTimestamp
        // hence, we need to iterate further through possible reference timestamps
        const auto hybridRefTimestamps = getAllTimestamps();
        auto tmpPos = std::find_if(hybridRefTimestamps.rbegin(), hybridRefTimestamps.rend(),
                                            [currNetworkTimestamp](const auto &entry){ return entry.first <= currNetworkTimestamp; });

        if (tmpPos != hybridRefTimestamps.rend()) {
            std::pair<std::reverse_iterator<std::map<TimePoint, ServerFileTimestamps>::const_iterator>, TimePoint> hybridPos =
                    std::make_pair(tmpPos, std::max({tmpPos->second.accessTime, tmpPos->second.changeTime, tmpPos->second.modifyTime}));
            ++tmpPos;

            TimePoint currMax;
            while (tmpPos != hybridRefTimestamps.rend()) {
                currMax = std::max({tmpPos->second.accessTime, tmpPos->second.changeTime, tmpPos->second.modifyTime});
                if (currMax > hybridPos.second)
                    hybridPos = std::make_pair(tmpPos, currMax);
                ++tmpPos;
            }

            if (writeOperation) {
                timestampsOfCurrVersion = TimeTriple(derivedFsTimestamp, ZERO_TIME_POINT, currNetworkTimestamp);
                hybridTimestamps[currNetworkTimestamp] = ServerFileTimestamps(
                                                  hybridPos.first->second.accessTime,
                                                  derivedFsTimestamp,
                                                  derivedFsTimestamp,
                                                  hybridPos.first->second.birthTime
                );
            } else {
                timestampsOfCurrVersion = TimeTriple(derivedFsTimestamp,
                                                    std::max({fsTimestampsPos->second.accessTime,
                                                                fsTimestampsPos->second.changeTime,
                                                                fsTimestampsPos->second.modifyTime}),
                                                    currNetworkTimestamp);
                hybridTimestamps[currNetworkTimestamp] = ServerFileTimestamps(
                                                    derivedFsTimestamp,
                                                    hybridPos.first->second.modifyTime,
                                                    hybridPos.first->second.changeTime,
                                                    hybridPos.first->second.birthTime
                );
            }
        } else {
            if (writeOperation) {
                timestampsOfCurrVersion = TimeTriple(derivedFsTimestamp, ZERO_TIME_POINT, currNetworkTimestamp);

            } else {
                timestampsOfCurrVersion = TimeTriple(derivedFsTimestamp,
                                                        std::max({fsTimestampsPos->second.accessTime,
                                                                    fsTimestampsPos->second.changeTime,
                                                                    fsTimestampsPos->second.modifyTime}),
                                                        currNetworkTimestamp);
            }
        }
    }
}


void pcapfs::SmbFile::serialize(boost::archive::text_oarchive &archive) {
    ServerFile::serialize(archive);
    archive << fsTimestamps;
    archive << hybridTimestamps;
    archive << fileVersions;
}


void pcapfs::SmbFile::deserialize(boost::archive::text_iarchive &archive) {
    ServerFile::deserialize(archive);
    archive >> fsTimestamps;
    archive >> hybridTimestamps;
    archive >> fileVersions;
}


bool pcapfs::SmbFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("smb", pcapfs::SmbFile::create, pcapfs::SmbFile::parse);
