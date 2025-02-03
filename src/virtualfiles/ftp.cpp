#include "ftp.h"
#include "../filefactory.h"
#include "ftp/ftp_manager.h"
#include "ftp/ftp_commands.h"
#include "ftp/ftp_utils.h"
#include "../exceptions.h"



std::vector<pcapfs::FilePtr> pcapfs::FtpFile::parse(FilePtr filePtr, Index &) {
    std::vector<FilePtr> resultVector(0);

    if (filePtr->connectionBreaks.empty())
        return resultVector;

    std::vector<pcapfs::FtpFileTransmissionData> port_transmission_data = getTransmissionDataForPort(filePtr);

    if (port_transmission_data.empty())
        return resultVector;

    const FtpFileTransmissionData d = getTransmissionFileData(filePtr, port_transmission_data);
    if (d.transmission_type.empty())
        return resultVector;

    if (d.transmission_type == ftp::FtpCommands::MLSD) {
        LOG_DEBUG << "FTP: handling MLSD file for " << d.transmission_file;
        handleMlsd(filePtr, d.transmission_file);
    } else {
        LOG_DEBUG << "FTP: found TCP connection with FTP file download";
        if (d.transmission_file.empty()) {
            // no filename given: set transmission type as filename and put file in root dir
            std::shared_ptr<pcapfs::FtpFile> resultPtr = std::make_shared<FtpFile>();
            resultPtr->parseResult(filePtr);
            resultPtr->isDirectory = false;
            resultPtr->setFilename(d.transmission_type);
            resultPtr->setParentDir(nullptr);
            resultPtr->fillGlobalProperties(filePtr);
            ftp::FtpManager::getInstance().addFtpFile(resultPtr->getFilename(), resultPtr);
        } else {
            std::string filePath = (d.transmission_file.at(d.transmission_file.size() - 1) == '/')
                                        ? d.transmission_file.substr(0, d.transmission_file.size() - 1)
                                        : d.transmission_file;
            if (d.transmission_type != ftp::FtpCommands::RETR)
                filePath += ("/" + d.transmission_type);
            ftp::FtpManager::getInstance().updateFtpFiles(filePath, d.transmission_type, filePtr);
        }
    }

    // circumvent duplicate as TCP file
    filePtr->flags.set(flags::PARSED);

    return resultVector;
}


std::vector<pcapfs::FtpFileTransmissionData>
pcapfs::FtpFile::getTransmissionDataForPort(pcapfs::FilePtr &filePtr) {
    ftp::FtpManager &manager = ftp::FtpManager::getInstance();
    const uint16_t src_port = stoi(filePtr->getProperty("srcPort"));
    const uint16_t dst_port = stoi(filePtr->getProperty("dstPort"));

    std::vector<FtpFileTransmissionData> transmission_data = manager.getFileTransmissionData(dst_port);
    if (transmission_data.empty()) {
        transmission_data = manager.getFileTransmissionData(src_port);
    }
    return transmission_data;
}


pcapfs::FtpFileTransmissionData
pcapfs::FtpFile::getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                         const std::vector<pcapfs::FtpFileTransmissionData> &transmission_data) {
    FtpFileTransmissionData d;
    const OffsetWithTime owt = filePtr->connectionBreaks.at(0);
    auto result = std::find_if(transmission_data.cbegin(), transmission_data.cend(),
                    [owt](const FtpFileTransmissionData &td){ return connectionBreaksInTimeSlot(owt.second, td.time_slot); });
    if (result != transmission_data.cend())
        d = *result;
    return d;
}


bool pcapfs::FtpFile::connectionBreaksInTimeSlot(TimePoint break_time, const pcapfs::TimeSlot &time_slot) {
    return time_slot.first <= break_time && break_time <= time_slot.second;
}


void pcapfs::FtpFile::handleMlsd(const FilePtr &filePtr, const std::string &filePath) {
    const Bytes data = filePtr->getBuffer();
    std::stringstream ss(std::string(data.begin(), data.end()));
    std::string line;
    while (std::getline(ss, line, '\n')) {
        try {
            const FtpFileMetaData metadata = ftp::parseMetadataLine(line);
            if (metadata.filename.empty())
                continue;

            std::string fullFilePath;
            if (metadata.filename == "/")
                fullFilePath = "FILES_FROM_" + filePtr->getProperty("dstIP");
            else
                fullFilePath = metadata.filename.at(0) == '/' ? "FILES_FROM_" + filePtr->getProperty("dstIP") + metadata.filename : filePath + metadata.filename;

            if (fullFilePath.at(fullFilePath.size() - 1) == '/')
                fullFilePath = fullFilePath.substr(0, fullFilePath.size() - 1);

            ftp::FtpManager::getInstance().updateFtpFilesFromMlsd(fullFilePath, metadata.isDir, metadata.modifyTime, filePtr);
        } catch (const PcapFsException &err){
            continue;
        }
    }
}


void pcapfs::FtpFile::handleAllFilesToRoot(const std::string &filePath, const ServerFileContextPtr &context) {

    LOG_DEBUG << "FTP: building up cascade of parent dir files for " << filePath;
    const size_t slashPos = filePath.rfind("/");
    if (filePath != "/" && slashPos != std::string::npos) {
        setFilename(std::string(filePath.begin()+slashPos+1, filePath.end()));
        LOG_DEBUG << "ftp file name: " << std::string(filePath.begin()+slashPos+1, filePath.end());
        const std::string remainder(filePath.begin(), filePath.begin()+slashPos);

        if(!remainder.empty() && remainder != "/") {
            LOG_DEBUG << "detected subdir(s)";
            LOG_DEBUG << "remainder: " << remainder;
            parentDir = ftp::FtpManager::getInstance().getAsParentDirFile(remainder, context);
        } else {
            // root directory has nullptr as parentDir
            parentDir = nullptr;
        }
    } else {
        setFilename(filePath);
        parentDir = nullptr;
    }
}


void pcapfs::FtpFile::parseResult(const pcapfs::FilePtr &filePtr) {

    const size_t numElements = filePtr->connectionBreaks.size();
    for (size_t i = 0; i < numElements; ++i) {

        const uint64_t &offset = filePtr->connectionBreaks.at(i).first;
        size_t size;
        if (i == numElements - 1) {
            size = filePtr->getFilesizeRaw() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        Fragment fragment;
        fragment.id = filePtr->getIdInIndex();
        fragment.start = offset;
        fragment.length = size;
        fragments.push_back(fragment);

        setFilesizeRaw(size);
        setFilesizeProcessed(getFilesizeRaw());
    }
}


void pcapfs::FtpFile::fillGlobalProperties(const FilePtr &filePtr) {
    fsTimestamps[filePtr->connectionBreaks.at(0).second] = ZERO_TIME_POINT;
    properties["protocol"] =  "ftp";
    filetype = "ftp";
    offsetType = filePtr->getFiletype();
    properties["srcIP"] = filePtr->getProperty("srcIP");
    properties["dstIP"] = filePtr->getProperty("dstIP");
    properties["srcPort"] = filePtr->getProperty("srcPort");
    properties["dstPort"] = filePtr->getProperty("dstPort");
    flags.set(flags::PROCESSED);
    idInIndex = ftp::FtpManager::getInstance().getNewId();
    parentDirId = parentDir ? parentDir->getIdInIndex() : (uint64_t)-1;
}


size_t pcapfs::FtpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
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


std::vector<pcapfs::FilePtr> const pcapfs::FtpFile::constructVersionFiles() {
    // TODO: make this smartly because in almost all cases we just have one version
    std::vector<FilePtr> resultVector;

    auto entryPos = fsTimestamps.crbegin();
    if (config.timestampMode != pcapfs::options::TimestampMode::NETWORK) {
        while (entryPos != fsTimestamps.crend() && entryPos->second == ZERO_TIME_POINT)
            ++entryPos;
        accessTime = changeTime = modifyTime = (entryPos == fsTimestamps.crend()) ? ZERO_TIME_POINT : entryPos->second;
    }
    else {
        accessTime = changeTime = modifyTime = (entryPos == fsTimestamps.crend()) ? ZERO_TIME_POINT : entryPos->first;
    }

    return resultVector;
}


bool pcapfs::FtpFile::constructSnapshotFile() {

    return true;
}


void pcapfs::FtpFile::serialize(boost::archive::text_oarchive &archive) {
    ServerFile::serialize(archive);
    archive << fsTimestamps;
}


void pcapfs::FtpFile::deserialize(boost::archive::text_iarchive &archive) {
    ServerFile::deserialize(archive);
    archive >> fsTimestamps;
}


bool pcapfs::FtpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ftp", pcapfs::FtpFile::create, pcapfs::FtpFile::parse);
