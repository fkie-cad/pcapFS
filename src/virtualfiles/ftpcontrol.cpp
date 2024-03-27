#include "ftpcontrol.h"

#include <iostream>
#include <iterator>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string.hpp>

#include "../filefactory.h"
#include "ftp/ftp_commands.h"
#include "ftp/ftp_response_codes.h"
#include "ftp/ftp_manager.h"

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

    LOG_DEBUG << "Found FTP traffic";
    std::shared_ptr<pcapfs::FtpControlFile> result = std::make_shared<FtpControlFile>();;
    std::shared_ptr<pcapfs::FtpControlFile> credentials = std::make_shared<FtpControlFile>();;

    fillGlobalProperties(result, filePtr);
    result->setFilename(".control");
    result->setProperty("defaultDataPort", DEFAULT_DATA_PORT);
    result->flags.set(pcapfs::flags::IS_METADATA);

    const size_t numElements = filePtr->connectionBreaks.size();
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


void pcapfs::FtpControlFile::parseUSERCredentials(std::shared_ptr<pcapfs::FtpControlFile> &result, size_t i,
                                                    pcapfs::FilePtr &filePtr,
                                                    std::shared_ptr<pcapfs::FtpControlFile> &credentials) {
    parseCredentials(credentials, filePtr, i);
    fillGlobalProperties(credentials, filePtr);
    result->setProperty("USER", "");
    credentials->setFilename(".credentials");
}


void pcapfs::FtpControlFile::parsePASSCredentials(pcapfs::FilePtr &filePtr,
                                                         std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                         std::shared_ptr<pcapfs::FtpControlFile> &credentials,
                                                         size_t i) {
    parseCredentials(credentials, filePtr, i);
     if (i == 0) {
        // USER part is not available, we have to initialize the result file nevertheless
        fillGlobalProperties(credentials, filePtr);
        credentials->setFilename(".credentials");
     }
    result->setProperty("PASS", "");
}


void pcapfs::FtpControlFile::parseCredentials(std::shared_ptr<pcapfs::FtpControlFile> result,
                                                pcapfs::FilePtr filePtr, size_t i) {
    const size_t numElements = filePtr->connectionBreaks.size();
    const uint64_t &offset = filePtr->connectionBreaks.at(i).first;
    const size_t size = calculateSize(filePtr, numElements, i, offset);
    const Fragment fragment = parseOffset(filePtr, offset, size);

    result->fragments.push_back(fragment);
    result->setFilesizeRaw(result->getFilesizeRaw() + size + DATA_DIRECTION_PREFIX_LN);
    result->setFilesizeProcessed(result->getFilesizeRaw());
}


void pcapfs::FtpControlFile::parseResult(std::shared_ptr<pcapfs::FtpControlFile> result,
                                           pcapfs::FilePtr filePtr, size_t i) {
    const size_t numElements = filePtr->connectionBreaks.size();
    const OffsetWithTime owt = filePtr->connectionBreaks.at(i);
    const uint64_t &offset = owt.first;
    const size_t size = calculateSize(filePtr, numElements, i, offset);
    const Bytes data = filePtr->getBuffer(); // copy of buffer ??
    char *raw_data = (char *) (data.data() + offset);
    const Fragment fragment = parseOffset(filePtr, offset, size);

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
    const Response response = parseResponse(raw_data, size, timestamp);
    handleResponseTypes(response, result);
    const uint8_t nr_of_lines = count(response.message.begin(), response.message.end(), '\n');

    return nr_of_lines;
}


size_t pcapfs::FtpControlFile::calculateSize(pcapfs::FilePtr filePtr, size_t numElements, size_t i, const uint64_t &offset) {
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


pcapfs::FtpControlFile::Response pcapfs::FtpControlFile::parseResponse(char *raw_data, size_t size, TimePoint timestamp) {
    const std::string raw_code = std::string(raw_data, RESPONSE_CODE_LN);
    const uint16_t code = stol(raw_code);
    std::string message = std::string(raw_data + RESPONSE_CODE_LN, size - RESPONSE_CODE_LN);
    boost::trim_left_if(message, boost::is_any_of(" "));

    return {code, message, timestamp};
}


void pcapfs::FtpControlFile::handleResponseTypes(const Response &response,
                                                        std::shared_ptr<pcapfs::FtpControlFile> &result) {
    if (response.code == FTPResponseCodes::EnteringPassiveMode)
        result->setProperty("activeDataPort", parsePassivePort(response.message));
    else if (response.code == FTPResponseCodes::EnteringExtendedPassiveMode)
        result->setProperty("activeDataPort", parseExtendedPassivePort(response.message));
}


/**
 * message format: "Entering Passive Mode (127,0,0,1,000,255)".
 * The last two numbers represent the port being two signs of a hex value.
 */
std::string const pcapfs::FtpControlFile::parsePassivePort(std::string message) {
    const size_t last_colon = message.rfind(',');
    const size_t blast_colon = message.rfind(',', last_colon - 1);
    const size_t closing_bracket = message.rfind(')');

    const uint8_t first_byte = stoi(message.substr(blast_colon + 1, (last_colon - blast_colon - 1)));
    const uint8_t second_byte = stoi(message.substr(last_colon + 1, (closing_bracket - last_colon - 1)));
    const uint16_t port = first_byte * 256 + second_byte;

    return std::to_string(port);
}

/**
 * message format: "Entering Extended Passive Mode (|||1337|)".
 * 1337 is the respective port.
 */
std::string const pcapfs::FtpControlFile::parseExtendedPassivePort(std::string message) {
    const auto last_delim = message.rfind('|');
    const auto second_last_delim = message.rfind('|', last_delim - 1);

    const std::string port = message.substr(second_last_delim + 1,  last_delim - second_last_delim - 1);
    return port;
}


uint8_t pcapfs::FtpControlFile::handleCommand(const std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                const pcapfs::FilePtr &filePtr, size_t i, size_t size) {
    const size_t numElements = filePtr->connectionBreaks.size();
    const uint64_t &offset = filePtr->connectionBreaks.at(i).first;
    const TimePoint cmd_timestamp = filePtr->connectionBreaks.at(i).second;
    Bytes data = filePtr->getBuffer();

    char *raw_data = (char *) (data.data() + offset);
    const Response response = getCommandResponse(filePtr, i + 1, numElements, data);
    const TimePoint timestamp_p2 = getTimestampAfterResponse(filePtr, i + 2, numElements, response);

    const Command command = parseCommand(raw_data, size);

    handleCommandTypes(result, command, response, TimeSlot(cmd_timestamp, timestamp_p2));

    return 1; // commands always have 1 line
}


pcapfs::TimePoint pcapfs::FtpControlFile::getTimestampAfterResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements,
                                                                    const pcapfs::FtpControlFile::Response &response) {
    return (numElements > i)
           ? filePtr->connectionBreaks.at(i).second
           : response.timestamp + std::chrono::seconds(1);
}


pcapfs::FtpControlFile::Response pcapfs::FtpControlFile::getCommandResponse(const pcapfs::FilePtr &filePtr, size_t i, size_t numElements,
                                                  pcapfs::Bytes &data) {
    if (numElements <= i) {
        return {0, "", TimePoint::min()};
    }

    const OffsetWithTime owt = filePtr->connectionBreaks.at(i);
    const uint64_t &offset = owt.first;
    char *response_data = (char *) (data.data() + offset);
    const size_t size = calculateSize(filePtr, numElements, i, offset);

    if (isResponse(response_data))
        return parseResponse(response_data, size, owt.second);
    else
        return {0, "", TimePoint::min()};
}


pcapfs::FtpControlFile::Command pcapfs::FtpControlFile::parseCommand(char *raw_data, size_t size) {
    std::string c = std::string(raw_data, size);
    c.erase(c.find_last_not_of(" \n\r\t") + 1);
    boost::trim(c);

    std::vector<std::string> params;
    boost::split(params, c, boost::is_any_of(" "));

    std::string command = params.at(0);
    params.erase(params.begin());

    return Command(command, params);
}


void pcapfs::FtpControlFile::handleCommandTypes(std::shared_ptr<FtpControlFile> result, const Command &cmd,
                                                  const Response &response, const TimeSlot &time_slot) {
    const std::string command = cmd.first;

    if (command == FTPCommands::PASS) {
        result->setProperty(FTPCommands::PASS, (cmd.second.size() > 0) ? cmd.second.at(0) : "");
    } else if (command == FTPCommands::USER) {
        result->setProperty(FTPCommands::USER, (cmd.second.size() > 0) ? cmd.second.at(0) : "");
    } else if (command == FTPCommands::PORT) {
        result->setProperty("activeDataPort", parsePassivePort(cmd.second.at(0)));
    } else if (command == FTPCommands::CWD && response.code == FTPResponseCodes::FileActionSuccessful && cmd.second.size() > 0) {
        std::string dir = cmd.second.at(0);
        if (dir.at(dir.length() - 1) != '/')
             dir += "/";

        if (dir.at(0) == '/')
            result->setProperty("cwd", dir);
        else {
            const std::string oldCwd = result->getProperty("cwd");
            if (!oldCwd.empty())
               result->setProperty("cwd", oldCwd + dir);
            else
                result->setProperty("cwd", dir);
        }
    } else if (response.code == FTPResponseCodes::FileStatusOK) {
        handleDataTransferCommand(result, cmd, time_slot);
    }
}


void pcapfs::FtpControlFile::handleDataTransferCommand(std::shared_ptr<pcapfs::FtpControlFile> &result,
                                                              const Command &cmd, const pcapfs::TimeSlot &time_slot) {
    const std::string command = cmd.first;
    const std::vector<std::string> params = cmd.second;
    std::string param;
    if (command == FTPCommands::MLSD) {
        param = result->getProperty("cwd").empty() ? "/" : result->getProperty("cwd");
        param += FTPCommands::MLSD;
    } else {
        param = (params.size() > 0) ?
                (result->getProperty("cwd").empty() ? "/" : result->getProperty("cwd")) + params.at(0) :
                "";
    }

    const FileTransmissionData data{param, command, time_slot};

    if (!result->getProperty("activeDataPort").empty()) {
        const uint16_t port = stoi(result->getProperty("activeDataPort"));
        FtpManager::getInstance().addFileTransmissionData(port, data);
    }
}


size_t pcapfs::FtpControlFile::read(uint64_t, size_t, const Index &idx, char *buf) {
    size_t i = 0;
    size_t read_count = 0;

    for (Fragment &fragment : fragments) {
        Bytes rawData = readRawData(idx, fragment);
        const uint8_t nr_of_lines = insertDirectionPrefixes(rawData, i);
        const uint16_t length_of_prefixes = nr_of_lines * DATA_DIRECTION_PREFIX_LN;

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
    const std::string prefix = (i % 2 == 0) ? DATA_DIRECTION_PREFIX_IN : DATA_DIRECTION_PREFIX_OUT;

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
