#include "ftp.h"
#include "../filefactory.h"
#include "ftp/ftp_manager.h"


std::vector<pcapfs::FilePtr> pcapfs::FtpFile::parse(FilePtr filePtr, Index &) {
    std::vector<FilePtr> resultVector(0);

    if (filePtr->connectionBreaks.empty())
        return resultVector;

    std::vector<pcapfs::FileTransmissionData> port_transmission_data = getTransmissionDataForPort(filePtr);

    if (port_transmission_data.empty())
        return resultVector;

    const FileTransmissionData d = getTransmissionFileData(filePtr, port_transmission_data);
    if (d.transmission_type.empty())
        return resultVector;

    std::shared_ptr<pcapfs::FtpFile> resultPtr = std::make_shared<FtpFile>();
    resultPtr->parseResult(filePtr);
    resultPtr->isDirectory = false;

    if (d.transmission_file.empty()) {
        resultPtr->setFilename(d.transmission_type);
        resultPtr->setParentDir(nullptr);
        resultPtr->fillGlobalProperties(filePtr);
        FtpManager::getInstance().addFtpFile(resultPtr->getFilename(), resultPtr);
    } else {
        resultPtr->handleAllFilesToRoot(d.transmission_file, filePtr);
        resultPtr->fillGlobalProperties(filePtr);
        FtpManager::getInstance().addFtpFile(d.transmission_file, resultPtr);
    }

    return resultVector;
}


std::vector<pcapfs::FileTransmissionData>
pcapfs::FtpFile::getTransmissionDataForPort(pcapfs::FilePtr &filePtr) {
    FtpManager &manager = FtpManager::getInstance();
    const uint16_t src_port = stoi(filePtr->getProperty("srcPort"));
    const uint16_t dst_port = stoi(filePtr->getProperty("dstPort"));

    std::vector<FileTransmissionData> transmission_data = manager.getFileTransmissionData(dst_port);
    if (transmission_data.empty()) {
        transmission_data = manager.getFileTransmissionData(src_port);
    }
    return transmission_data;
}


pcapfs::FileTransmissionData
pcapfs::FtpFile::getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                         const std::vector<pcapfs::FileTransmissionData> &transmission_data) {
    FileTransmissionData d;
    const OffsetWithTime owt = filePtr->connectionBreaks.at(0);
    auto result = std::find_if(transmission_data.cbegin(), transmission_data.cend(),
                    [owt](const FileTransmissionData &td){ return connectionBreaksInTimeSlot(owt.second, td.time_slot); });
    if (result != transmission_data.cend())
        d = *result;
    return d;
}


bool pcapfs::FtpFile::connectionBreaksInTimeSlot(TimePoint break_time, const pcapfs::TimeSlot &time_slot) {
    return time_slot.first <= break_time && break_time <= time_slot.second;
}


void pcapfs::FtpFile::handleAllFilesToRoot(const std::string &filePath, const FilePtr &offsetFilePtr) {

    const size_t slashPos = filePath.rfind("/");
    if (filePath != "/" && slashPos != std::string::npos) {
        setFilename(std::string(filePath.begin()+slashPos+1, filePath.end()));
        LOG_TRACE << "ftp file name: " << std::string(filePath.begin()+slashPos+1, filePath.end());
        const std::string remainder(filePath.begin(), filePath.begin()+slashPos);

        if(!remainder.empty() && remainder != "/") {
            LOG_TRACE << "detected subdir(s)";
            LOG_TRACE << "remainder: " << remainder;
            parentDir = FtpManager::getInstance().getAsParentDirFile(remainder, offsetFilePtr);
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
    accessTime = filePtr->connectionBreaks.at(0).second;
    modifyTime = filePtr->connectionBreaks.at(0).second;
    changeTime = filePtr->connectionBreaks.at(0).second;
    birthTime = filePtr->connectionBreaks.at(0).second;
    setProperty("protocol", "ftp");
    setFiletype("ftp");
    setOffsetType(filePtr->getFiletype());
    setProperty("srcIP", filePtr->getProperty("srcIP"));
    setProperty("dstIP", filePtr->getProperty("dstIP"));
    setProperty("srcPort", filePtr->getProperty("srcPort"));
    setProperty("dstPort", filePtr->getProperty("dstPort"));
    setIdInIndex(FtpManager::getInstance().getNewId());
    parentDirId = parentDir ? parentDir->getIdInIndex() : (uint64_t)-1;
}


size_t pcapfs::FtpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment &fragment = fragments.at(0);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    return filePtr->read(fragment.start + startOffset, length, idx, buf);
}


bool pcapfs::FtpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ftp", pcapfs::FtpFile::create, pcapfs::FtpFile::parse);
