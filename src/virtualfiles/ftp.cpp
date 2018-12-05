#include "ftp.h"

#include <iostream>

#include "../filefactory.h"


std::vector<pcapfs::FilePtr> pcapfs::FtpFile::parse(FilePtr filePtr, Index &) {
    std::vector<FilePtr> resultVector(0);

    if (filePtr->connectionBreaks.empty())
        return resultVector;

    std::vector<pcapfs::FileTransmissionData> port_transmission_data = getTransmissionDataForPort(filePtr);

    if (port_transmission_data.empty())
        return resultVector;

    FileTransmissionData d = getTransmissionFileData(filePtr, port_transmission_data);
    if (d.transmission_type.empty())
        return resultVector;

    std::shared_ptr<pcapfs::FtpFile> resultPtr = std::make_shared<FtpFile>();
    fillGlobalProperties(resultPtr, filePtr);

    std::string f_name = constructFileName(d);
    resultPtr->setFilename(f_name);

    size_t numElements = filePtr->connectionBreaks.size();

    for (size_t i = 0; i < numElements; ++i) {
        parseResult(resultPtr, filePtr, i);
    }

    resultVector.push_back(resultPtr);

    return resultVector;
}


std::vector<pcapfs::FileTransmissionData>
pcapfs::FtpFile::getTransmissionDataForPort(pcapfs::FilePtr &filePtr) {
    FTPPortBridge &bridge = FTPPortBridge::getInstance();
    uint16_t src_port = stoi(filePtr->getProperty("srcPort"));
    uint16_t dst_port = stoi(filePtr->getProperty("dstPort"));

    std::vector<FileTransmissionData> transmission_data = bridge.getFileTransmissionData(dst_port);
    if (transmission_data.empty()) {
        transmission_data = bridge.getFileTransmissionData(src_port);
    }
    return transmission_data;
}


pcapfs::FileTransmissionData
pcapfs::FtpFile::getTransmissionFileData(const pcapfs::FilePtr &filePtr,
                                         const std::vector<pcapfs::FileTransmissionData> &transmission_data) {
    FileTransmissionData d;
    OffsetWithTime owt = filePtr->connectionBreaks.at(0);
    for (const FileTransmissionData &td : transmission_data) {
        if (connectionBreaksInTimeSlot(owt.second, td.time_slot)) {
            d = td;
            break;
        }
    }
    return d;
}


bool pcapfs::FtpFile::connectionBreaksInTimeSlot(TimePoint break_time, const pcapfs::TimeSlot &time_slot) {
    return time_slot.first <= break_time && break_time <= time_slot.second;
}


std::string pcapfs::FtpFile::constructFileName(const pcapfs::FileTransmissionData &d) {
    std::string f_name = d.transmission_file;
    replace(f_name.begin(), f_name.end(), '/', '-');
    if (!f_name.empty())f_name = "-" + f_name;
    f_name = d.transmission_type + f_name;

    return f_name;
}


void
pcapfs::FtpFile::parseResult(std::shared_ptr<pcapfs::FtpFile> result, pcapfs::FilePtr filePtr, size_t i) {
    size_t numElements = filePtr->connectionBreaks.size();
    uint64_t &offset = filePtr->connectionBreaks.at(i).first;
    size_t size = calculateSize(filePtr, numElements, i, offset);
    SimpleOffset soffset = parseOffset(filePtr, offset, size);

    result->offsets.push_back(soffset);
    result->setFilesizeRaw(result->getFilesizeRaw() + size);
}


size_t
pcapfs::FtpFile::calculateSize(pcapfs::FilePtr filePtr, size_t numElements, size_t i, uint64_t &offset) {
    size_t size;
    if (i == numElements - 1) {
        size = filePtr->getFilesizeRaw() - offset;
    } else {
        size = filePtr->connectionBreaks.at(i + 1).first - offset;
    }

    return size;
}


SimpleOffset pcapfs::FtpFile::parseOffset(pcapfs::FilePtr &filePtr, const uint64_t &offset, size_t size) {
    SimpleOffset soffset;
    soffset.id = filePtr->getIdInIndex();
    soffset.start = offset;
    soffset.length = size;
    return soffset;
}


void pcapfs::FtpFile::fillGlobalProperties(std::shared_ptr<pcapfs::FtpFile> &result, FilePtr &filePtr) {
    result->setTimestamp(filePtr->connectionBreaks.at(0).second);
    result->setProperty("protocol", "ftp");
    result->setFiletype("ftpdata");
    result->setOffsetType(filePtr->getFiletype());
    result->setProperty("srcIP", filePtr->getProperty("srcIP"));
    result->setProperty("dstIP", filePtr->getProperty("dstIP"));
    result->setProperty("srcPort", filePtr->getProperty("srcPort"));
    result->setProperty("dstPort", filePtr->getProperty("dstPort"));
}


size_t pcapfs::FtpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    SimpleOffset &offset = offsets.at(0);
    FilePtr filePtr = idx.get({offsetType, offset.id});
    return filePtr->read(offset.start + startOffset, length, idx, buf);
}


bool pcapfs::FtpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ftp", pcapfs::FtpFile::create, pcapfs::FtpFile::parse);