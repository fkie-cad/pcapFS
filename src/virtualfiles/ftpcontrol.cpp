#include "ftpcontrol.h"

#include <iostream>
#include <iterator>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string.hpp>

#include "../filefactory.h"
#include "ftp/ftp_commands.h"
#include "ftp/ftp_response_codes.h"
#include "ftp/ftp_port_bridge.h"

const std::string pcapfs::FtpControlFile::DEFAULT_DATA_PORT = "20";
const std::string pcapfs::FtpControlFile::COMMAND_PORT = "21";
const uint8_t pcapfs::FtpControlFile::RESPONSE_CODE_LN = 3;
const std::pair<uint8_t, uint8_t> pcapfs::FtpControlFile::ASCII_INT_RANGE(48, 57);
const std::string pcapfs::FtpControlFile::DATA_DIRECTION_PREFIX_IN = "[<] ";
const std::string pcapfs::FtpControlFile::DATA_DIRECTION_PREFIX_OUT = "[>] ";
const uint8_t pcapfs::FtpControlFile::DATA_DIRECTION_PREFIX_LN = DATA_DIRECTION_PREFIX_IN.size();


std::vector<pcapfs::FilePtr> pcapfs::FtpControlFile::parse(FilePtr filePtr, Index &) {
    std::vector<FilePtr> resultVector(0);

    if (filePtr->connectionBreaks.empty())
        return resultVector;

    if (!isClientCommand(filePtr) && !isServerResponse(filePtr))
        return resultVector;

    std::shared_ptr<pcapfs::FtpControlFile> result = std::make_shared<FtpControlFile>();;
    std::shared_ptr<pcapfs::FtpControlFile> credentials = std::make_shared<FtpControlFile>();;

    fillGlobalProperties(result, filePtr);
    result->setFilename(".control");
    result->setProperty("defaultDataPort", DEFAULT_DATA_PORT);
    result->flags.set(pcapfs::flags::IS_METADATA);

    size_t numElements = filePtr->connectionBreaks.size();
    for (size_t i = 0; i < numElements; ++i) {
        parseResult(result, filePtr, i);

        if (result->getProperty(FTPCommands::USER) != "") {
            parseUSERCredentials(result, i, filePtr, credentials);
        } else if (result->getProperty(FTPCommands::PASS) != "") {
            parsePASSCredentials(filePtr, result, credentials, i);
        }
    }

    if (!result->fragments.empty()) resultVector.push_back(result);
    if (!credentials->fragments.empty()) resultVector.push_back(credentials);

    return resultVector;
}


bool pcapfs::FtpControlFile::isClientCommand(FilePtr filePtr) {
    return filePtr->getProperty("dstPort") == pcapfs::FtpControlFile::COMMAND_PORT;
}


bool pcapfs::FtpControlFile::isServerResponse(FilePtr filePtr) {
    return filePtr->getProperty("srcPort") == pcapfs::FtpControlFile::COMMAND_PORT;
}


void pcapfs::FtpControlFile::fillGlobalProperties(std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                         FilePtr &filePtr) {
    result->setTimestamp(filePtr->connectionBreaks.at(0).second);
    result->setProperty("protocol", "ftp");
    result->setFiletype("ftpcontrol");
    result->setOffsetType(filePtr->getFiletype());
    result->setProperty("srcIP", filePtr->getProperty("srcIP"));
    result->setProperty("dstIP", filePtr->getProperty("dstIP"));
    result->setProperty("srcPort", filePtr->getProperty("srcPort"));
    result->setProperty("dstPort", filePtr->getProperty("dstPort"));
}


void
pcapfs::FtpControlFile::parseUSERCredentials(std::shared_ptr<pcapfs::FtpControlFile> &result, size_t i,
                                                    pcapfs::FilePtr &filePtr,
                                                    std::shared_ptr<pcapfs::FtpControlFile> &credentials) {
    parseCredentials(credentials, filePtr, i);
    fillGlobalProperties(credentials, filePtr);
    result->setProperty("USER", "");
    credentials->setFilename(".credentials");
}


void pcapfs::FtpControlFile::parsePASSCredentials(const pcapfs::FilePtr &filePtr,
                                                         std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                         const std::shared_ptr<pcapfs::FtpControlFile> &credentials,
                                                         size_t i) {
    parseCredentials(credentials, filePtr, i);
    result->setProperty("PASS", "");
}


void
pcapfs::FtpControlFile::parseCredentials(std::shared_ptr<pcapfs::FtpControlFile> result,
                                                pcapfs::FilePtr filePtr, size_t i) {
    size_t numElements = filePtr->connectionBreaks.size();
    uint64_t &offset = filePtr->connectionBreaks.at(i).first;
    size_t size = calculateSize(filePtr, numElements, i, offset);
    Fragment fragment = parseOffset(filePtr, offset, size);

    result->fragments.push_back(fragment);
    result->setFilesizeRaw(result->getFilesizeRaw() + size + DATA_DIRECTION_PREFIX_LN);
    result->setFilesizeProcessed(result->getFilesizeRaw());
}


void
pcapfs::FtpControlFile::parseResult(std::shared_ptr<pcapfs::FtpControlFile> result,
                                           pcapfs::FilePtr filePtr, size_t i) {
    size_t numElements = filePtr->connectionBreaks.size();
    OffsetWithTime owt = filePtr->connectionBreaks.at(i);
    uint64_t &offset = owt.first;
    size_t size = calculateSize(filePtr, numElements, i, offset);
    Bytes data = filePtr->getBuffer(); // copy of buffer ??
    char *raw_data = (char *) (data.data() + offset);
    Fragment fragment = parseOffset(filePtr, offset, size);

    uint8_t nr_of_lines;

    if (isResponse(raw_data)) {
        nr_of_lines = handleResponse(result, size, raw_data, owt.second);
    } else {
        nr_of_lines = handleCommand(result, filePtr, i, size);
    }

    result->fragments.push_back(fragment);
    result->setFilesizeRaw(result->getFilesizeRaw() + size + DATA_DIRECTION_PREFIX_LN * nr_of_lines);
    result->setFilesizeProcessed(result->getFilesizeRaw());

}


uint8_t pcapfs::FtpControlFile::handleResponse(std::shared_ptr<FtpControlFile> &result, size_t size,
                                                      char *raw_data, TimePoint timestamp) {
    Response response = parseResponse(raw_data, size, timestamp);
    handleResponseTypes(response, result);
    uint8_t nr_of_lines = count(response.message.begin(), response.message.end(), '\n');

    return nr_of_lines;
}


size_t
pcapfs::FtpControlFile::calculateSize(pcapfs::FilePtr filePtr, size_t numElements, size_t i, uint64_t &offset) {
    if (isLastElement(numElements, i)) {
        return filePtr->getFilesizeRaw() - offset;
    } else {
        return filePtr->connectionBreaks.at(i + 1).first - offset;
    }
}


bool pcapfs::FtpControlFile::isLastElement(size_t numElements, size_t i) {
    return i == numElements - 1;
}


Fragment pcapfs::FtpControlFile::parseOffset(pcapfs::FilePtr &filePtr, const uint64_t &offset, size_t size) {
    Fragment fragment;
    fragment.id = filePtr->getIdInIndex();
    fragment.start = offset;
    fragment.length = size;

    return fragment;
}


bool pcapfs::FtpControlFile::isResponse(char *raw_data) {
    for (uint8_t i = 0; i < RESPONSE_CODE_LN; i++) {
        if (!charIsInt(raw_data[i])) return false;
    }

    return true;
}

bool pcapfs::FtpControlFile::charIsInt(char c) {
    return ASCII_INT_RANGE.first <= c && c <= ASCII_INT_RANGE.second;
}


pcapfs::FtpControlFile::Response
pcapfs::FtpControlFile::parseResponse(char *raw_data, size_t size, TimePoint timestamp) {
    std::string raw_code = std::string(raw_data, RESPONSE_CODE_LN);
    uint16_t code = stol(raw_code);
    std::string message = std::string(raw_data + RESPONSE_CODE_LN, size - RESPONSE_CODE_LN);
    boost::trim_left_if(message, boost::is_any_of(" "));

    return {code, message, timestamp};
}


void pcapfs::FtpControlFile::handleResponseTypes(const Response &response,
                                                        std::shared_ptr<pcapfs::FtpControlFile> &result) {
    if (response.code == FTPResponseCodes::EnteringPassiveMode) {
        handleEnteringPassiveMode(response.message, result);
    }
}


void pcapfs::FtpControlFile::handleEnteringPassiveMode(const std::string &message,
                                                              std::shared_ptr<pcapfs::FtpControlFile> &result) {
    uint16_t port = parsePassivePort(message);
//    FTPPortBridge::getInstance().addPort(port);

    result->setProperty("activeDataPort", std::to_string(port));
//    std::cout << "FtpControlFile::handleEnteringPassiveMode\n";
//    std::cout << " - active port: "<<result->getProperty("activeDataPort")<<"\n";
}


/**
 * message format: "Entering Passive Mode (127,0,0,1,000,255)".
 * The last two numbers represent the port beeing two signs of a hex value.
 */
uint16_t pcapfs::FtpControlFile::parsePassivePort(std::string message) {
    size_t last_colon = message.rfind(',');
    size_t blast_colon = message.rfind(',', last_colon - 1);
    size_t closing_bracket = message.rfind(')');

    uint8_t first_byte = stoi(message.substr(blast_colon + 1, (last_colon - blast_colon - 1)));
    uint8_t second_byte = stoi(message.substr(last_colon + 1, (closing_bracket - last_colon - 1)));
    uint16_t port = first_byte * 256 + second_byte;

    return port;
}


uint8_t pcapfs::FtpControlFile::handleCommand(const std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                     const pcapfs::FilePtr &filePtr, size_t i, size_t size) {
    size_t numElements = filePtr->connectionBreaks.size();
    uint64_t &offset = filePtr->connectionBreaks.at(i).first;
    TimePoint cmd_timestamp = filePtr->connectionBreaks.at(i).second;
    Bytes data = filePtr->getBuffer();

    char *raw_data = (char *) (data.data() + offset);
    Response response = getCommandResponse(filePtr, i + 1, numElements, data);
    TimePoint timestamp_p2 = getTimestampAfterResponse(filePtr, i + 2, numElements, response);

    Command command = parseCommand(raw_data, size);

    handleCommandTypes(result, command, response, TimeSlot(cmd_timestamp, timestamp_p2));

    return 1; // commands always have 1 line
}


pcapfs::TimePoint
pcapfs::FtpControlFile::getTimestampAfterResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements,
                                                         const pcapfs::FtpControlFile::Response &response) {
    return (numElements > i)
           ? filePtr->connectionBreaks.at(i).second
           : response.timestamp + std::chrono::seconds(1);
}


pcapfs::FtpControlFile::Response
pcapfs::FtpControlFile::getCommandResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements,
                                                  pcapfs::Bytes &data) {
    if (numElements <= i) {
        return {0, "", TimePoint::min()};
    }

    OffsetWithTime owt = filePtr->connectionBreaks.at(i);
    uint64_t &offset = owt.first;
    char *response_data = (char *) (data.data() + offset);
    size_t size = calculateSize(filePtr, numElements, i, offset);

    if (isResponse(response_data))
        return parseResponse(response_data, size, owt.second);
    else
        return {0, "", TimePoint::min()};
}


pcapfs::FtpControlFile::Command
pcapfs::FtpControlFile::parseCommand(char *raw_data, size_t size) {
    std::string c = std::string(raw_data, size);
    c.erase(c.find_last_not_of(" \n\r\t") + 1);
    boost::trim(c);

    std::vector<std::string> params;
    boost::split(params, c, boost::is_any_of(" "));

    std::string command = params[0];
    params.erase(params.begin());

    return Command(command, params);
}


void
pcapfs::FtpControlFile::handleCommandTypes(std::shared_ptr<FtpControlFile> result, const Command &cmd,
                                                  const Response &response, const TimeSlot &time_slot) {
    std::string command = cmd.first;

    if (command == FTPCommands::PASS) {
        handlePASS(result, cmd);
    } else if (command == FTPCommands::USER) {
        handleUSER(result, cmd);
    } else if (command == FTPCommands::PORT) {
        handlePORT(result, cmd);
    } else if (response.code == FTPResponseCodes::FileStatusOK) {
        handleDataTransferCommand(result, cmd, time_slot);
    }
}


void
pcapfs::FtpControlFile::handlePASS(std::shared_ptr<pcapfs::FtpControlFile> &result, const Command &cmd) {
    std::string pass = (cmd.second.size() > 0) ? cmd.second[0] : "";
    result->setProperty(FTPCommands::PASS, pass);
}


void
pcapfs::FtpControlFile::handleUSER(std::shared_ptr<pcapfs::FtpControlFile> &result, const Command &cmd) {
    std::string user = (cmd.second.size() > 0) ? cmd.second[0] : "";
    result->setProperty(FTPCommands::USER, user);
}


void
pcapfs::FtpControlFile::handlePORT(std::shared_ptr<pcapfs::FtpControlFile> &result, const Command &cmd) {
    uint16_t port = parsePassivePort(cmd.second[0]);

    result->setProperty("activeDataPort", std::to_string(port));
}


void pcapfs::FtpControlFile::handleDataTransferCommand(std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                              const Command &cmd, const pcapfs::TimeSlot &time_slot) {
    std::string command = cmd.first;
    std::vector<std::string> params = cmd.second;
    std::string param = (params.size() > 0) ? params[0] : "";

    FileTransmissionData data{param, command, time_slot};

    if (!result->getProperty("activeDataPort").empty()) {
        uint16_t port = stoi(result->getProperty("activeDataPort"));
        FTPPortBridge::getInstance().addFileTransmissionData(port, data);
    }
}


/**
 *
 * @param startOffset
 * @param length total length of buf
 * @param idx
 * @param buf writing buffer
 * @return
 */
size_t pcapfs::FtpControlFile::read(uint64_t, size_t, const Index &idx, char *buf) {
    size_t i = 0;
    size_t read_count = 0;
    uint16_t length_of_prefixes = 0;

    for (Fragment &fragment : fragments) {
        Bytes rawData = readRawData(idx, fragment);
        uint8_t nr_of_lines = insertDirectionPrefixes(rawData, i);
        length_of_prefixes = nr_of_lines * DATA_DIRECTION_PREFIX_LN;

        memcpy(&buf[read_count], (char *) rawData.data(), fragment.length + length_of_prefixes);

        read_count += fragment.length + length_of_prefixes;
        i++;
    }

    return read_count;
}


pcapfs::Bytes pcapfs::FtpControlFile::readRawData(const pcapfs::Index &idx, const Fragment &fragment) const {
    Bytes rawData;
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({this->offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, (char *) rawData.data());

    return rawData;
}


uint8_t pcapfs::FtpControlFile::insertDirectionPrefixes(pcapfs::Bytes &rawData, size_t i) const {
    uint8_t nr_of_lines = 0;
    std::string prefix = (i % 2 == 0) ? DATA_DIRECTION_PREFIX_IN : DATA_DIRECTION_PREFIX_OUT;

    rawData.insert(rawData.begin(), prefix.begin(), prefix.end());

    auto it = rawData.begin();
    while (it != rawData.end()) {
        if (*it == '\n') {
            nr_of_lines++;
            if (it + 1 != rawData.end()) {
                it = rawData.insert(it + 1, prefix.begin(), prefix.end());
                it = it + DATA_DIRECTION_PREFIX_LN;
                continue;
            }
        }

        ++it;
    }

    return nr_of_lines;
}


bool pcapfs::FtpControlFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("ftpcontrol", pcapfs::FtpControlFile::create,
                                               pcapfs::FtpControlFile::parse);
