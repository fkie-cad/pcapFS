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
            ((options::LOWER_SNIP_SPECIFIED && accessTime < config.snip.first) ||
            (options::UPPER_SNIP_SPECIFIED && accessTime >= config.snip.second))){
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
        if (!result.count(entry.first))
            result[entry.first] = entry.second;
    }
    return result;
}


void pcapfs::SmbFile::deduplicateVersions(const Index &idx) {
    if (fragments.size() == 0 || (fragments.size() == 1 && fragments.at(0).length == 0))
        return;

    // add current saved fragments as newest version
    fileVersions.emplace(timestampsOfCurrVersion, ServerFileVersion<smb::SmbTimestamps>(fragments, clientIPs, isCurrentlyReadOperation));

    if (fileVersions.size() > 1) {
        LOG_DEBUG << "deduplicating file versions of " << filename;
        std::vector<std::map<TimeTriple, ServerFileVersion<smb::SmbTimestamps>>::iterator> toBeErased;
        auto currVersion = fileVersions.begin();
        auto cmpVersion = std::next(currVersion);

        while (cmpVersion != fileVersions.end()) {
            const Bytes a = this->getContentForFragments(idx, currVersion->second.fragments);
            const Bytes b = this->getContentForFragments(idx, cmpVersion->second.fragments);
            if ((a.size() == b.size()) && a == b) {
                LOG_TRACE << "found duplicate versions";
                // copy clientIPs and time points of file accesses to version that is kept
                for (const auto &ip: cmpVersion->second.clientIPs) {
                    currVersion->second.clientIPs.insert(ip);
                }
                for (const auto &ac: cmpVersion->second.accesses) {
                    currVersion->second.accesses.insert(ac);
                }
                currVersion->second.accesses.insert(cmpVersion->first);

                // implicitly, a duplicate file version pair is deduplicated according to
                // their access types (read/write) in the following way:
                // (read, read) or (read, write) -> read
                // (write, write) or (write, read) -> write

                toBeErased.push_back(cmpVersion);
                // only advance cmpVersion. currVersion stays the same
                cmpVersion++;

            } else {
                LOG_TRACE << "versions are different";
                currVersion = cmpVersion;
                cmpVersion = std::next(currVersion);
            }
        }

        for (const auto &pos: toBeErased)
            fileVersions.erase(pos);
    }

    // insert timestamps to the corresponding file versions
    auto fsTimestampsPos = fsTimestamps.rbegin();
    auto hybridTimestampsPos = hybridTimestamps.rbegin();

    for (auto versionPos = fileVersions.rbegin(); versionPos != fileVersions.rend(); ++versionPos) {
        while (fsTimestampsPos != fsTimestamps.rend()) {
            if (fsTimestampsPos->first >= versionPos->first.networkTime) {
                versionPos->second.timestamps.fsTimestamps.emplace(fsTimestampsPos->first, fsTimestampsPos->second);
            } else {
                if (versionPos->second.readOperation &&
                    std::chrono::duration_cast<std::chrono::seconds>(versionPos->first.networkTime - fsTimestampsPos->first).count() == 0) {
                    // also include the fs timestamp from the previous create response, when we have a read
                    versionPos->second.timestamps.fsTimestamps.emplace(fsTimestampsPos->first, fsTimestampsPos->second);
                }
                ++fsTimestampsPos;
                break;
            }
            ++fsTimestampsPos;
        }

        while (hybridTimestampsPos != hybridTimestamps.rend() && hybridTimestampsPos->first >= versionPos->first.networkTime) {
            versionPos->second.timestamps.hybridTimestamps.emplace(hybridTimestampsPos->first, hybridTimestampsPos->second);
            ++hybridTimestampsPos;
        }

        if (std::next(versionPos) == fileVersions.rend() && versionPos->second.readOperation) {
            // for the first file version, add also all fs timestamps which are older, when he have a read access
            while (fsTimestampsPos != fsTimestamps.rend()) {
                versionPos->second.timestamps.fsTimestamps.emplace(fsTimestampsPos->first, fsTimestampsPos->second);
                ++fsTimestampsPos;
            }
        }
    }

    fsTimestamps.erase(fsTimestampsPos.base(), fsTimestamps.end());
    hybridTimestamps.erase(hybridTimestampsPos.base(), hybridTimestamps.end());

    // if the file operation for the first file version is write, there might still be fs and hybrid timestamps left in
    // the corresponding "global" maps. These are used, when --snapshot or --snip is set accordingly
}


pcapfs::ServerFileTimestampsPosRevIt pcapfs::SmbFile::getPosOfTimestampCandidate(const ServerFileTimestampsMap& timestampsMap) {
    ServerFileTimestampsPosRevIt resultPos;

    if (options::SNAPSHOT_SPECIFIED) {
        if (!options::LOWER_SNIP_SPECIFIED && !options::UPPER_SNIP_SPECIFIED) {
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                         [](const auto &entry) { return entry.first < config.snapshot; });
            } else {
                // hybrid or fs
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                         [](const auto &entry) { return entry.second < config.snapshot; });
            }

        } else if (options::LOWER_SNIP_SPECIFIED && !options::UPPER_SNIP_SPECIFIED) {
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first >= config.snip.first) && (entry.first < config.snapshot);
                                    }
                                );
            } else {
                // hybrid or fs
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first >= config.snip.first) && (entry.second < config.snapshot);
                                        }
                                    );
            }

        } else if (!options::LOWER_SNIP_SPECIFIED && options::UPPER_SNIP_SPECIFIED) {
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first < config.snip.second) && (entry.first < config.snapshot);
                                    }
                                );
            } else {
                // hybrid or fs
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first < config.snip.second) && (entry.second < config.snapshot);
                                        }
                                    );
            }

        } else {
            // upper and lower snip boundary is specified
            if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first < config.snip.second) && (entry.first >= config.snip.first) &&
                                                    (entry.first < config.snapshot);
                                    }
                                );
            } else {
                // hybrid or fs
                resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first < config.snip.second) && (entry.first >= config.snip.first) &&
                                                    (entry.second < config.snapshot);
                                        }
                                    );
            }
        }

    } else {
        // --snapshot is not set
        if (options::LOWER_SNIP_SPECIFIED && !options::UPPER_SNIP_SPECIFIED) {
            resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                    [](const auto &entry){ return entry.first >= config.snip.first; });

        } else if (!options::LOWER_SNIP_SPECIFIED && options::UPPER_SNIP_SPECIFIED) {
            // upper snip boundary is not specified
            resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                    [](const auto &entry){ return entry.first < config.snip.second; });

        } else if (options::LOWER_SNIP_SPECIFIED && options::UPPER_SNIP_SPECIFIED) {
            // upper and lower snip boundary is specified
            resultPos = std::find_if(timestampsMap.crbegin(), timestampsMap.crend(),
                                        [](const auto &entry) {
                                            return (entry.first < config.snip.second) &&
                                                    (entry.first >= config.snip.first);
                                        }
                                    );
        } else {
            // snapshot is not set and upper as well as lower snip boundary is not specified.
            // This case does not occur because with this configuration, the function is not called
            resultPos = timestampsMap.crend();
        }
    }

    return resultPos;
}


bool pcapfs::SmbFile::tryMatchTimestampsToSnip(const ServerFileTimestampsMap& locFsTimestamps, const ServerFileTimestampsMap& locHybridTimestamps) {

    ServerFileTimestampsPosRevIt fsPos = getPosOfTimestampCandidate(locFsTimestamps);

    if (config.timestampMode == pcapfs::options::TimestampMode::FS && fsPos != locFsTimestamps.crend()) {
        accessTime = fsPos->second.accessTime;
        changeTime = fsPos->second.changeTime;
        modifyTime = fsPos->second.modifyTime;
        return true;

    } else if (config.timestampMode != pcapfs::options::TimestampMode::FS) {
        // hybrid or network timestamp mode
        ServerFileTimestampsPosRevIt targetTimestampsPos;
        ServerFileTimestampsPosRevIt hybridPos = getPosOfTimestampCandidate(locHybridTimestamps);

        if (hybridPos != locHybridTimestamps.crend() &&
            (fsPos == locFsTimestamps.crend() || fsPos->second < hybridPos->second)) {
            targetTimestampsPos = hybridPos;
        } else if (fsPos != locFsTimestamps.crend()) {
             targetTimestampsPos = fsPos;
        } else {
             return false;
        }

        if (config.timestampMode == pcapfs::options::TimestampMode::HYBRID) {
            accessTime = targetTimestampsPos->second.accessTime;
            changeTime = targetTimestampsPos->second.changeTime;
            modifyTime = targetTimestampsPos->second.modifyTime;
        } else {
            // network mode
            accessTime = changeTime = modifyTime = targetTimestampsPos->first;
        }

        return true;
    }

    return false;
}


std::vector<pcapfs::FilePtr> const pcapfs::SmbFile::constructVersionFiles() {
    std::vector<FilePtr> resultVector;
    const size_t numFileVersions = fileVersions.size();

    if (numFileVersions <= 1) {
        // metadata file, directory file or only one read/write (deduplicated)
        std::map<pcapfs::TimePoint, pcapfs::ServerFileTimestamps> referenceTimestamps;
        if (numFileVersions == 0) {
            referenceTimestamps = config.timestampMode == pcapfs::options::TimestampMode::FS ? fsTimestamps : getAllTimestamps();
        } else {
            // we have one file version
            referenceTimestamps = config.timestampMode == pcapfs::options::TimestampMode::FS ?
                                    fileVersions.begin()->second.timestamps.fsTimestamps :
                                    fileVersions.begin()->second.timestamps.getAllTimestamps();
        }

        if (referenceTimestamps.empty() ||
            (numFileVersions == 1 && config.timestampMode == pcapfs::options::TimestampMode::FS &&
                !fileVersions.begin()->second.readOperation)) {
            // no timestamps saved or fs mode and the only file version is from write operation
            accessTime = changeTime = modifyTime = ZERO_TIME_POINT;
        } else {
            // take newest timestamp (or nearest timestamp if snip option is set)
            // (snip is always w.r.t. network timestamps)
            auto target = referenceTimestamps.crbegin();
            if (options::UPPER_SNIP_SPECIFIED) {
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
    for (auto currVersion = fileVersions.begin(); currVersion != fileVersions.end(); ++currVersion, ++i) {
        const auto currAccesses = currVersion->second.accesses;
        const auto networkTimeOfCurrVersion = currVersion->first.networkTime;
        // it might be sufficient to only check the newest access instead of all
        if (((options::LOWER_SNIP_SPECIFIED && networkTimeOfCurrVersion < config.snip.first) ||
            (options::UPPER_SNIP_SPECIFIED && networkTimeOfCurrVersion >= config.snip.second)) &&
            std::all_of(currAccesses.cbegin(), currAccesses.cend(),
                            [](const auto &access) {
                                return (options::LOWER_SNIP_SPECIFIED && access.networkTime < config.snip.first) ||
                                        (options::UPPER_SNIP_SPECIFIED && access.networkTime >= config.snip.second);
                                }
                        )
            ) {
            // file version does not belong to snip interval
            continue;
        }

        SmbFilePtr newFile(this->clone());
        newFile->setFilename(filename + "@" + std::to_string(i));

        const auto currSmbTimestamps = currVersion->second.timestamps;
        if (currSmbTimestamps.fsTimestamps.empty() && currSmbTimestamps.hybridTimestamps.empty()) {
            // should not happen
            newFile->setAccessTime(ZERO_TIME_POINT);
            newFile->setChangeTime(ZERO_TIME_POINT);
            newFile->setModifyTime(ZERO_TIME_POINT);

        } else if (config.timestampMode == pcapfs::options::TimestampMode::NETWORK) {
            TimePoint selectedTimestamp;

            // it suffices to check options::UPPER_SNIP_SPECIFIED (instead of also LOWER_SNIP_SPECIFIED) because of the snip interval check above
            if (options::UPPER_SNIP_SPECIFIED) {
                // get the network timestamp of a file access inside the snip interval that was observed closest to the upper snip bound
                const auto pos = std::find_if(currAccesses.crbegin(), currAccesses.crend(),
                                                [](const auto &entry){ return entry.networkTime < config.snip.second; });

                if (pos == currAccesses.rend()) {
                    // All network times for the file version accesses are newer than the upper snip bound.
                    // Together with the snip check from above and the fact that networkTimeOfCurrVersion
                    // is always older than all saved access network times, we know that networkTimeOfCurrVersion
                    // is the appropriate timestamp to set
                    selectedTimestamp = networkTimeOfCurrVersion;
                } else {
                    selectedTimestamp = pos->networkTime;
                }
            } else {
                if (currAccesses.empty()) {
                    selectedTimestamp = networkTimeOfCurrVersion;
                } else {
                    selectedTimestamp = currAccesses.rbegin()->networkTime;
                }
            }
            newFile->setAccessTime(selectedTimestamp);
            newFile->setChangeTime(selectedTimestamp);
            newFile->setModifyTime(selectedTimestamp);

        } else if (config.timestampMode == pcapfs::options::TimestampMode::HYBRID) {
            ServerFileTimestamps selectedTimestamps;
            if (options::UPPER_SNIP_SPECIFIED) {
                // get the hybrid or fs timestamp that was observed inside the snip interval and was observed
                // at the network time closest to the upper snip bound
                const auto hybridPos = std::find_if(currSmbTimestamps.hybridTimestamps.crbegin(), currSmbTimestamps.hybridTimestamps.crend(),
                                                [](const auto &entry){ return entry.first < config.snip.second; });

                const auto fsPos = std::find_if(currSmbTimestamps.fsTimestamps.crbegin(), currSmbTimestamps.fsTimestamps.crend(),
                                                [](const auto &entry){ return entry.first < config.snip.second; });

                // select hybrid or fs time, whichever has newer timestamps
                if (hybridPos != currSmbTimestamps.hybridTimestamps.crend() &&
                    (fsPos == currSmbTimestamps.fsTimestamps.crend() || fsPos->second < hybridPos->second)) {
                     selectedTimestamps = hybridPos->second;
                } else if (fsPos != currSmbTimestamps.fsTimestamps.crend()) {
                     selectedTimestamps = fsPos->second;
                } else {
                     selectedTimestamps = ServerFileTimestamps(ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT);;
                }
            } else {
                const auto highesthybridTimestampPos = currSmbTimestamps.hybridTimestamps.rbegin();
                const auto highestFsTimestampPos = currSmbTimestamps.fsTimestamps.rbegin();
                // select the timestamp, that has been observed latest
                if (currSmbTimestamps.fsTimestamps.empty() ||
                    (!currSmbTimestamps.hybridTimestamps.empty() &&
                        highesthybridTimestampPos->first >= highestFsTimestampPos->first)) {

                    selectedTimestamps = highesthybridTimestampPos->second;
                } else {
                    selectedTimestamps = highestFsTimestampPos->second;
                }
            }
            newFile->setAccessTime(selectedTimestamps.accessTime);
            newFile->setChangeTime(selectedTimestamps.changeTime);
            newFile->setModifyTime(selectedTimestamps.modifyTime);

        } else if (config.timestampMode == pcapfs::options::TimestampMode::FS && currVersion->second.readOperation) {
            ServerFileTimestamps selectedTimestamps;
            if (options::UPPER_SNIP_SPECIFIED) {
                // get the fs timestamp that was observed inside the snip interval and was observed
                // at the network time closest to the upper snip bound
                const auto pos = std::find_if(currSmbTimestamps.fsTimestamps.crbegin(), currSmbTimestamps.fsTimestamps.crend(),
                                                [](const auto &entry){ return entry.first < config.snip.second; });

                if (pos == currSmbTimestamps.fsTimestamps.crend()) {
                    // should not happen
                    selectedTimestamps = ServerFileTimestamps(ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT);
                } else {
                    selectedTimestamps = pos->second;
                }
            } else {
                if (currSmbTimestamps.fsTimestamps.empty()) {
                    selectedTimestamps = ServerFileTimestamps(ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT, ZERO_TIME_POINT);
                } else {
                    selectedTimestamps = currSmbTimestamps.fsTimestamps.rbegin()->second;
                }
            }
            newFile->setAccessTime(selectedTimestamps.accessTime);
            newFile->setChangeTime(selectedTimestamps.changeTime);
            newFile->setModifyTime(selectedTimestamps.modifyTime);

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
    }

    if (config.showMetadata && resultVector.empty() && (options::LOWER_SNIP_SPECIFIED || options::UPPER_SNIP_SPECIFIED)) {
        // no file version fits into the specified snip interval
        // Nevertheless, it can be the case that the file has been accessed during this interval (but not with read/write).
        // Then, we want to display the file as metadata file
        bool displayAsMetadataFile = false;

        for (auto currVersion = fileVersions.rbegin(); currVersion != fileVersions.rend(); ++currVersion) {
            if (tryMatchTimestampsToSnip(currVersion->second.timestamps.fsTimestamps, currVersion->second.timestamps.hybridTimestamps)) {
                displayAsMetadataFile = true;
                break;
            }
        }

        if (displayAsMetadataFile ||
            (!fileVersions.begin()->second.readOperation && tryMatchTimestampsToSnip(fsTimestamps, hybridTimestamps))) {
            // we have matching timestamps in the snip interval -> display file as metadata file
            // (the second if condition additionally checks whether a "globally" saved timestamp fits inside the snip interval when
            // the operation for the first file version is write)
            filesizeRaw = filesizeProcessed = 0;
            fragments.clear();
            flags.set(flags::IS_METADATA);
        } else {
            // no matching timestamps in snip interval
            donotDisplay = true;
        }
    }

    return resultVector;
}


bool pcapfs::SmbFile::trySetAsMetadataFile(const ServerFileTimestampsMap &fsTimestamps, const ServerFileTimestampsMap &hybridTimestamps) {
    if (tryMatchTimestampsToSnip(fsTimestamps, hybridTimestamps)) {
        fragments.clear(),
        filesizeRaw = filesizeProcessed = 0;
        flags.set(pcapfs::flags::IS_METADATA);
        return true;
    } else {
        return false;
    }
}


bool pcapfs::SmbFile::constructSnapshotFile() {
    if (fileVersions.size() == 0) {
        // metadata file. we only need to find and select suitable timestamps from the "global" maps
        return tryMatchTimestampsToSnip(fsTimestamps, hybridTimestamps);
    }

    ServerFileVersion<smb::SmbTimestamps> targetFileVersion;
    TimePoint networkTimeOfTargetVersion;

    // select matching file version w.r.t. snapshot time
    std::reverse_iterator<std::map<TimeTriple, ServerFileVersion<smb::SmbTimestamps>>::const_iterator> fileVersionPos;
    if (config.timestampMode == options::TimestampMode::NETWORK) {
        fileVersionPos = std::find_if(fileVersions.rbegin(), fileVersions.rend(),
                                        [](const auto &version){ return version.first.networkTime < config.snapshot; });
    } else if (config.timestampMode == options::TimestampMode::FS) {
        fileVersionPos = std::find_if(fileVersions.rbegin(), fileVersions.rend(),
                                        [](const auto &version) {
                                            return version.first.fsTime != ZERO_TIME_POINT && version.first.fsTime < config.snapshot;
                                        }
                                    );
    } else {
        // hybrid mode
        fileVersionPos = std::find_if(fileVersions.rbegin(), fileVersions.rend(),
                                        [](const auto &version){ return version.first.hybridTime < config.snapshot; });
    }

    if (fileVersionPos == fileVersions.rend()) {
        // timestamp key of oldest file version is newer than snapshot time
        targetFileVersion = fileVersions.begin()->second;
        if (targetFileVersion.readOperation) {
            // when the first file version corresponds to read operation, it can still be the correct version to display
            networkTimeOfTargetVersion = fileVersions.begin()->first.networkTime;
        } else {
            // first file version corresponds to write operation
            // Then, we probably have saved timestamps left in the "global" timestamp maps of the smb file.
            // If there are suitbale timestamps w.r.t the snapshot (and potentially the snip interval),
            // we display the SMB file as metadata file
            return trySetAsMetadataFile(fsTimestamps, hybridTimestamps);
        }
    } else {
        targetFileVersion = fileVersionPos->second;
        networkTimeOfTargetVersion = fileVersionPos->first.networkTime;
    }

    if ((options::LOWER_SNIP_SPECIFIED &&
            config.snip.first > (targetFileVersion.accesses.empty() ?
                                networkTimeOfTargetVersion :
                                std::max({networkTimeOfTargetVersion, targetFileVersion.accesses.rbegin()->networkTime}))) ||
        (options::UPPER_SNIP_SPECIFIED && config.snip.second < networkTimeOfTargetVersion)) {
        // the lower snip boundary is higher than the network time of the file version's last read/write access or
        // the upper snip boundary is lower than the network time of the file version's first read/write access
        // -> only display as empty file (given that a suitable timestamp exists)
        return trySetAsMetadataFile(targetFileVersion.timestamps.fsTimestamps, targetFileVersion.timestamps.hybridTimestamps);
    }

    if (tryMatchTimestampsToSnip(targetFileVersion.timestamps.fsTimestamps, targetFileVersion.timestamps.hybridTimestamps)) {
        fragments = targetFileVersion.fragments;
        clientIPs = targetFileVersion.clientIPs;
        filesizeRaw = filesizeProcessed = std::accumulate(fragments.begin(), fragments.end(), 0,
                                                    [](size_t counter, const auto &frag){ return counter + frag.length; });
        return true;
    } else {
        LOG_DEBUG << "for smb file " << filename << ", the snapshot time is outside of the snip interval -> we do not display the file";
        return false;
    }
}


void pcapfs::SmbFile::initializeFilePtr(const smb::SmbContextPtr &smbContext, const std::string &filePath, const smb::FileMetaDataPtr &metaData) {
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
    properties[prop::srcIP] = smbContext->offsetFile->getProperty(prop::srcIP);
    properties[prop::dstIP] = smbContext->offsetFile->getProperty(prop::dstIP);
    properties[prop::srcPort] = smbContext->offsetFile->getProperty(prop::srcPort);
    properties[prop::dstPort] = smbContext->offsetFile->getProperty(prop::dstPort);
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
