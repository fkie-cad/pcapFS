#include "cobaltstrike.h"
#include "../filefactory.h"
#include "../logging.h"
#include "../exceptions.h"
#include "../cobaltstrike/cs_manager.h"
#include "../cobaltstrike/cs_callback_codes.h"
#include "../cobaltstrike/cs_command_codes.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <endian.h>
#include <sstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <regex>
#include <numeric>


std::vector<pcapfs::FilePtr> pcapfs::CobaltStrikeFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);
    if (filePtr->getFiletype() != "http"|| filePtr->flags.test(pcapfs::flags::IS_METADATA) ||
        (!CobaltStrikeManager::getInstance().isKnownConnection(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"), filePtr->getProperty("srcIP")) &&
        !CobaltStrikeManager::getInstance().isKnownConnection(filePtr->getProperty("srcIP"), filePtr->getProperty("srcPort"), filePtr->getProperty("dstIP"))))
        return resultVector;

    std::shared_ptr<CobaltStrikeFile> resultPtr = std::make_shared<CobaltStrikeFile>();

    Fragment fragment;
    fragment.id = filePtr->getIdInIndex();
    fragment.start = 0;
    fragment.length = filePtr->getFilesizeRaw();
    resultPtr->fragments.push_back(fragment);
    resultPtr->setFilesizeRaw(fragment.length);
    resultPtr->setOffsetType(filePtr->getFiletype());
    resultPtr->setFiletype("cobaltstrike");
    resultPtr->setTimestamp(filePtr->getTimestamp());
    resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    resultPtr->setProperty("protocol", "cobaltstrike");
    resultPtr->setProperty("domain", filePtr->getProperty("domain"));
    resultPtr->setProperty("uri", filePtr->getProperty("uri"));

    std::string command;
    std::stringstream ss;
    ss << std::chrono::duration_cast<std::chrono::milliseconds>(filePtr->getTimestamp().time_since_epoch()).count();
    const std::string timestamp = ss.str();

    if (isHttpPost(filePtr->getFilename())) {
        resultPtr->cobaltStrikeKey = CobaltStrikeManager::getInstance().getConnectionData(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"),
                                                                                            filePtr->getProperty("srcIP"))->aesKey;
        resultPtr->setFilename(timestamp + "-response");
        resultPtr->fromClient = true;
        resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx, command));
        resultPtr->flags.set(pcapfs::flags::PROCESSED);
        resultVector.push_back(resultPtr);


    } else if (isHttpResponse(filePtr->getFilename())) {
        CobaltStrikeConnectionPtr connData = CobaltStrikeManager::getInstance().getConnectionData(filePtr->getProperty("srcIP"), filePtr->getProperty("srcPort"),
                                                                                                    filePtr->getProperty("dstIP"));
        resultPtr->cobaltStrikeKey = connData->aesKey;
        resultPtr->fromClient = false;

        try{
            resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx, command));
            resultPtr->setFilename(timestamp + "-" + command);
        } catch (PcapFsException &err) {
            // this might be a beacon config file
            resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());
            resultPtr->setFilename(timestamp + "-beaconconfig");
        }

        for (auto embeddedFileInfo : resultPtr->checkEmbeddedFiles(idx)) {
            std::shared_ptr<CobaltStrikeFile> embeddedFilePtr = std::make_shared<CobaltStrikeFile>();
            Fragment embeddedFragment;
            embeddedFragment.id = filePtr->getIdInIndex();
            embeddedFragment.start = 0;
            embeddedFragment.length = fragment.length;
            embeddedFilePtr->fragments.push_back(embeddedFragment);

            embeddedFilePtr->setFilesizeRaw(embeddedFileInfo->size);
            embeddedFilePtr->setFilesizeProcessed(embeddedFileInfo->size);

            embeddedFilePtr->embeddedFileIndex = embeddedFileInfo->id;

            embeddedFilePtr->setOffsetType(filePtr->getFiletype());
            embeddedFilePtr->setFiletype("cobaltstrike");

            if (!embeddedFileInfo->filename.empty()) {
                std::string filename = embeddedFileInfo->filename;
                if (filename.find("\\") != std::string::npos) {
                    std::vector<std::string> tokens;
                    boost::split(tokens, filename, [](char c) { return c == 0x5C; });
                    filename = tokens.back();
                }
                if (embeddedFileInfo->isChunk)
                    embeddedFilePtr->setFilename(resultPtr->getFilename() + "_" + filename + "_part" + std::to_string(embeddedFileInfo->id));
                else
                    embeddedFilePtr->setFilename(resultPtr->getFilename()  + "_" + filename);
            }
            else
                embeddedFilePtr->setFilename(resultPtr->getFilename()  + "_embedded_file" + std::to_string(embeddedFileInfo->id));

            embeddedFilePtr->setTimestamp(filePtr->getTimestamp());
            embeddedFilePtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
            embeddedFilePtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
            embeddedFilePtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
            embeddedFilePtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
            embeddedFilePtr->setProperty("domain", filePtr->getProperty("domain"));
            embeddedFilePtr->setProperty("uri", filePtr->getProperty("uri"));
            embeddedFilePtr->setProperty("protocol", "cobaltstrike");


            embeddedFilePtr->cobaltStrikeKey = connData->aesKey;
            embeddedFilePtr->fromClient = false;
            embeddedFilePtr->flags.set(pcapfs::flags::IS_EMBEDDED_FILE);
            embeddedFilePtr->flags.set(pcapfs::flags::PROCESSED);

            const std::string embeddedFileCommand = embeddedFileInfo->command;
            if (embeddedFileCommand == "COMMAND_UPLOAD") {
                CobaltStrikeManager::getInstance().addFilePtrToUploadedFiles(embeddedFileInfo->filename, embeddedFilePtr, true);
                embeddedFilePtr->flags.set(pcapfs::flags::CS_DO_NOT_SHOW);

            } else if (embeddedFileCommand == "COMMAND_UPLOAD_CONTINUE") {
                CobaltStrikeManager::getInstance().addFilePtrToUploadedFiles(embeddedFileInfo->filename, embeddedFilePtr, false);
                embeddedFilePtr->flags.set(pcapfs::flags::CS_DO_NOT_SHOW);
            }
            resultVector.push_back(embeddedFilePtr);
        }

        resultPtr->flags.set(pcapfs::flags::PROCESSED);
        resultVector.push_back(resultPtr);
    }

    return resultVector;
}


size_t pcapfs::CobaltStrikeFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));

    Bytes decryptedData;
    if (flags.test(pcapfs::flags::IS_EMBEDDED_FILE))
        decryptedData = decryptEmbeddedFile(rawData);
    else {
        try {
            decryptedData = decryptPayload(rawData);
        } catch (PcapFsException &err) {
            decryptedData = rawData;
        }
    }
    memcpy(buf, decryptedData.data() + startOffset, length);
    return std::min(decryptedData.size() - startOffset, length);
}


bool pcapfs::CobaltStrikeFile::isHttpPost(const std::string &filename) {
    try {
        return std::regex_search(filename, std::regex("^[0-9\\-]+_POST"));
    } catch (std::regex_error &err) {
        return false;
    }
}


bool pcapfs::CobaltStrikeFile::isHttpResponse(const std::string &filename) {
    const std::vector<std::string> requestMethods = {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "TRACE",
            "OPTIONS",
            "CONNECT",
            "PATCH",
            "UNKNOWN"
    };
    try {
        return std::none_of(requestMethods.begin(), requestMethods.end(), [filename](const std::string &s){
                            return std::regex_search(filename, std::regex("^[0-9\\-]+_" + s)); });
    } catch (std::regex_error &err) {
        return false;
    }
}


size_t pcapfs::CobaltStrikeFile::calculateProcessedSize(const Index &idx, std::string &command) {
    Bytes rawData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    if (flags.test(pcapfs::flags::IS_EMBEDDED_FILE))
        return decryptEmbeddedFile(rawData).size();
    else {
        Bytes decryptedData = decryptPayload(rawData);
        if (!fromClient)
            command = extractServerCommand(decryptedData);
        return decryptedData.size();
    }
}


std::string const pcapfs::CobaltStrikeFile::extractServerCommand(const Bytes &payload) {
    const std::string input(payload.begin(), payload.end());
    std::smatch match;
    try {
        std::regex_search(input, match, std::regex("COMMAND_([A-Z0-9_]+)"));
    } catch (std::regex_error &err) {
        return "command";
    }
    if (match.size() == 2)
        return boost::algorithm::to_lower_copy(match[1].str());
    else
        return "command";
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::decryptPayload(const Bytes &input) {
    if (input.size() < 32 || cobaltStrikeKey.empty()) {
        return input;
    }

    Bytes decryptedData, dataToDecrypt;
    // truncate hmac at the end
    if (fromClient) {
        // client data has additional field in front to truncate
        decryptedData.resize(input.size() - 20);
        dataToDecrypt.assign(input.begin()+4, input.end()-16);
    } else {
        decryptedData.resize(input.size() - 16);
        dataToDecrypt.assign(input.begin(), input.end()-16);
    }

    if (opensslDecryptCS(dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        return input;
    }

    Bytes result = fromClient ? parseDecryptedClientContent(decryptedData) : parseDecryptedServerContent(decryptedData);
    if (result.empty())
        result = input;

    return result;
}


int pcapfs::CobaltStrikeFile::opensslDecryptCS(const Bytes &dataToDecrypt, Bytes &decryptedData) {

    // we can't use the crypto::opensslDecrypt function because
    // cobalt strike pads in a way that EVP_DecryptFinal doesn't like
    // => we have to unpad manually later on
    int error = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() failed" << std::endl;
        error = 1;
    }
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, cobaltStrikeKey.data(), (const unsigned char*) "abcdefghijklmnop", 0) != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() failed" << std::endl;
        error = 1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, cobaltStrikeKey.data(), (const unsigned char*) "abcdefghijklmnop") != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() failed" << std::endl;
        error = 1;
    }

    int outlen;
    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &outlen, dataToDecrypt.data(), dataToDecrypt.size()) != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() failed" << std::endl;
        error = 1;
    }

    if (error)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_cleanup(ctx);
    return error;
 }


pcapfs::Bytes const pcapfs::CobaltStrikeFile::parseDecryptedClientContent(const Bytes &data) {
    Bytes result;
    Bytes temp(data.begin(), data.end());

    uint32_t counter = be32toh(*((uint32_t*) (temp.data())));
    //uint32_t data_length = be32toh(*((uint32_t*) (tempc+4))); // is including padding bytes and additional values at the end
    uint32_t callback_code = be32toh(*((uint32_t*) (temp.data()+8)));
    const std::string callback_string = callback_code < 33 ? CSCallback::codes[callback_code] : "CALLBACK_UNKNOWN";

    std::stringstream ss;
    ss << "Counter: " << counter << "\nCallback: " << callback_code << " " << callback_string;

    if (callback_string == "CALLBACK_ERROR" && std::isprint(*(temp.begin()+24))) {
        auto zero_it = std::find_if(temp.begin()+24, temp.end(), [](unsigned char c){ return c == 0x00; });
        const std::string param(temp.begin()+24, zero_it);
        ss << "\nParameter: " << param << "\n---------------------------------------------------------\n";
        const std::string metadata = ss.str();
        //Bytes weirdPayload(std::find_if(zero_it, temp.end(), [](unsigned char c){ return c != 0x00; }), temp.end());
        //if (weirdPayload.back() == 0x00)
        //    weirdPayload.erase(std::find_if(weirdPayload.rbegin(), weirdPayload.rend(), [](unsigned char c){ return c != 0x00; }).base(), weirdPayload.end());
        result.insert(result.end(), metadata.begin(), metadata.end());
        //result.insert(result.end(), weirdPayload.begin(), weirdPayload.end());

    } else {
        temp.erase(temp.begin(), temp.begin()+12);
        //temp.erase(temp.begin()+data_length, temp.end());
        if (callback_string == "CALLBACK_PENDING") {
            temp.erase(temp.begin(), temp.begin()+4); // has an additional field to exclude
            if (temp.back() == 0x00)
                temp.erase(std::find_if(temp.rbegin(), temp.rend(), [](unsigned char c){ return c != 0x00; }).base(), temp.end());
        } else if (std::isprint(temp.front()) || std::isspace(temp.front())) {
            temp.erase(std::find_if(temp.rbegin(), temp.rend(), [](unsigned char c){ return c == 0x0A; }).base(), temp.end());
        }

        ss << "\n---------------------------------------------------------\n";
        const std::string metadata = ss.str();
        result.insert(result.end(), metadata.begin(), metadata.end());
        result.insert(result.end(), temp.begin(), temp.end());
    }

    return result;
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::parseDecryptedServerContent(const Bytes &data) {
    Bytes temp(data.begin(), data.end());
    Bytes output;

    const time_t timestamp = be32toh(*((uint32_t*) temp.data()));
    const uint32_t data_size = be32toh(*((uint32_t*) (temp.data()+4)));
    if (data_size > data.size()) {
        LOG_INFO << "cobalt strike: parsed length of server message is invalid";
        throw PcapFsException("parsed length of server message is invalid");
    }

    std::stringstream ss;
    ss << "Timestamp: " << std::put_time(std::localtime(&timestamp), "%Y-%m-%d %I:%M:%S %p")
        << "\nData Size: " << data_size;
    const std::string header = ss.str();
    output.insert(output.end(), header.begin(), header.end());

    temp.erase(temp.begin(), temp.begin()+8);

    // one server message can contain multiple consecutive commands incl. parameters
    // we move along the parsed length fields
    uint32_t curr_len = 8; // after the "global" header with timestamp and data_size
    while (curr_len <= data_size) {
        ss.str("");
        ss << "\n---------------------------------------------------------\n";

        uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) {
            // we have probably no command content
            LOG_WARNING << "cobalt strike: parsed server command is invalid";
            return data;
        }
        std::string command = CSCommands::codes[command_code];
        uint32_t args_len = be32toh(*((uint32_t*) (temp.data()+4)));
        ss << "Command: " << command_code << " " << command
            << "\nArgs Len: " << args_len << std::endl;

        temp.erase(temp.begin(), temp.begin()+8);
        if (args_len + 8 > data_size) {
            LOG_WARNING << "cobalt strike: parsed argument length of server command is invalid";
            return data;
        }

        if (command == "COMMAND_LS") {
            uint32_t ls_counter = be32toh(*((uint32_t*) temp.data()));
            //uint32_t ls_dir_len = be32toh(*((uint32_t*) (ls_params+4)));
            std::string ls_dir(temp.begin()+8, temp.begin()+args_len);
            ss << "Counter: " << ls_counter <<  "\nDirectory: " << ls_dir;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_CD") {
            std::string dir(temp.begin(), temp.begin()+args_len);
            ss << "Directory: " << dir;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_RM"){
            std::string file(temp.begin(), temp.begin()+args_len);
            ss << "File: " << file;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_SLEEP") {
            uint32_t sleep = be32toh(*((uint32_t*) temp.data()));
            uint32_t jitter = be32toh(*((uint32_t*) (temp.data()+4)));
            ss << "Sleep: " << sleep << "\nJitter: " << jitter;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_EXECUTE_JOB") {
            size_t args_len_without_padding = getLengthWithoutPadding(temp, args_len);
            size_t currPos = 0;
            while (currPos < args_len_without_padding) {
                uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len_without_padding - currPos) {
                    LOG_WARNING << "cobalt strike: parsed argument length of COMMAND_EXECUTE_JOB is invalid";
                    return data;
                }
                std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_JOB_REGISTER" || command == "COMMAND_JOB_REGISTER_MSGMODE") {
            size_t currPos = 8; // we have 2 unknown additional fields in front
            while (currPos < args_len) {
                uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len - currPos) {
                    LOG_WARNING << "cobalt strike: parsed argument length of COMMAND_JOB_REGISTER is invalid";
                    return data;
                }
                //std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                std::string argument(temp.begin()+4+currPos, std::find_if(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen,
                                                                        [](unsigned char c){ return c == 0x00; }));
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_UPLOAD" || command == "COMMAND_UPLOAD_CONTINUE") {
            uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
            if (filenameLen > args_len) {
                LOG_WARNING << "cobalt strike: parsed filename length of upload command is invalid";
                return data;
            }
            const std::string filename(temp.begin()+4, temp.begin()+4+filenameLen);
            ss << "File: " << filename;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_INLINE_EXECUTE_OBJECT" || command == "COMMAND_SPAWN_TOKEN_X86" ||
                    command == "COMMAND_SPAWNX64" || command == "COMMAND_SPAWN_TOKEN_X64") {
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else {
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());
            output.insert(output.end(), temp.begin(), temp.begin()+args_len);
        }

        curr_len += args_len + 8;
        temp.erase(temp.begin(), temp.begin()+args_len);
    }

    return output;
 }


size_t pcapfs::CobaltStrikeFile::getLengthWithoutPadding(const Bytes &input, uint32_t inputLength) {
    Bytes temp(input.begin(), input.begin()+inputLength);
    temp.erase(std::find_if(temp.rbegin(), temp.rend(), [](unsigned char c){ return c != 0x00; }).base(), temp.end());
    return temp.size();
}


std::vector<pcapfs::EmbeddedFileInfoPtr> pcapfs::CobaltStrikeFile::checkEmbeddedFiles(const Index &idx) {
    Bytes rawData, decryptedData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    return extractEmbeddedFileInfos(rawData);
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::decryptEmbeddedFile(const Bytes &input) {
    if (input.size() < 32 || cobaltStrikeKey.empty())
        return input;

    Bytes decryptedData(input.size() - 16);
    Bytes dataToDecrypt(input.begin(), input.end() - 16);

    if (opensslDecryptCS(dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        return input;
    }

    Bytes temp(decryptedData.begin(), decryptedData.end());

    const uint32_t dataSize = be32toh(*((uint32_t*) (temp.data()+4)));
    temp.erase(temp.begin(), temp.begin()+8);

    uint32_t currOffset = 8; // header size with timestamp and data_size
    for (uint64_t currIndex = 0; currOffset < dataSize; ++currIndex) {

        uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) { // we have probably no command content
            return decryptedData;
        }
        std::string command = CSCommands::codes[command_code];
        uint32_t argsLen = be32toh(*((uint32_t*) (temp.data()+4)));

        temp.erase(temp.begin(), temp.begin()+8);
        if (argsLen + 8 > dataSize) {
            LOG_WARNING << "cobalt strike: parsed argument length of server command is invalid";
            return input;
        }

        if (currIndex == embeddedFileIndex) {
            if (command == "COMMAND_SPAWN_TOKEN_X86" || command == "COMMAND_SPAWN_TOKEN_X64" ||
                command == "COMMAND_SPAWNX64" || command == "COMMAND_INLINE_EXECUTE_OBJECT"){
                return Bytes(temp.begin(), temp.begin()+argsLen);
            } else if (command == "COMMAND_UPLOAD" || command == "COMMAND_UPLOAD_CONTINUE") {
                uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
                if (filenameLen > argsLen) {
                    LOG_WARNING << "cobalt strike: parsed filename length of upload command is invalid";
                    return input;
                }
                return Bytes(temp.begin()+4+filenameLen, temp.begin()+argsLen);
            }
        }
        currOffset += argsLen + 8;
        temp.erase(temp.begin(), temp.begin()+argsLen);
    }
    return decryptedData;
 }


std::vector<pcapfs::EmbeddedFileInfoPtr> pcapfs::CobaltStrikeFile::extractEmbeddedFileInfos(const Bytes &input) {
    std::vector<EmbeddedFileInfoPtr> result;

    if (input.size() < 32 || cobaltStrikeKey.empty())
        return result;

    Bytes decryptedData(input.size() - 16);
    Bytes dataToDecrypt(input.begin(), input.end() - 16);

    if (opensslDecryptCS(dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        return result;
    }

    Bytes temp(decryptedData.begin(), decryptedData.end());

    const uint32_t dataSize = be32toh(*((uint32_t*) (temp.data()+4)));
    temp.erase(temp.begin(), temp.begin()+8);

    uint32_t currOffset = 8; // header size with timestamp and data_size
    for (uint64_t currIndex = 0; currOffset < dataSize; ++currIndex) {
        EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();

        uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) { // we have probably no command content
            return result;
        }
        std::string command = CSCommands::codes[command_code];
        uint32_t argsLen = be32toh(*((uint32_t*) (temp.data()+4)));

        temp.erase(temp.begin(), temp.begin()+8);
        if (argsLen + 8 > dataSize)
            break;

        if (command == "COMMAND_UPLOAD") {
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->size = argsLen - 4;
            uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
            if (filenameLen < argsLen) {
                const std::string filename(temp.begin()+4, temp.begin()+4+filenameLen);
                embeddedFileInfo->filename = filename;
                embeddedFileInfo->size = embeddedFileInfo->size - filenameLen;

            }
            result.push_back(embeddedFileInfo);

        } else if (command == "COMMAND_UPLOAD_CONTINUE"){
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->size = argsLen - 4;
            embeddedFileInfo->isChunk = true;
            uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
            if (filenameLen < argsLen) {
                const std::string filename(temp.begin()+4, temp.begin()+4+filenameLen);
                embeddedFileInfo->filename = filename;
                embeddedFileInfo->size = embeddedFileInfo->size - filenameLen;
            }
            result.push_back(embeddedFileInfo);

        } else if (command == "COMMAND_SPAWN_TOKEN_X86" || command == "COMMAND_SPAWN_TOKEN_X64" ||
                command == "COMMAND_SPAWNX64" || command == "COMMAND_INLINE_EXECUTE_OBJECT") {
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->size = argsLen;
            result.push_back(embeddedFileInfo);
        }
        currOffset += argsLen + 8;
        temp.erase(temp.begin(), temp.begin()+argsLen);
    }

    return result;
}


bool pcapfs::CobaltStrikeFile::showFile() {
    if (config.showAll)
        return true;
    else if (flags.test(flags::IS_EMBEDDED_FILE))
        return !flags.test(flags::CS_DO_NOT_SHOW);
    return true;
}


void pcapfs::CobaltStrikeFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    archive << cobaltStrikeKey;
    archive << (fromClient ? 1 : 0);
    archive << embeddedFileIndex;

}


void pcapfs::CobaltStrikeFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    int i;
    archive >> cobaltStrikeKey;
    archive >> i;
    fromClient = i ? true : false;
    archive >> embeddedFileIndex;
}


bool pcapfs::CobaltStrikeFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("cobaltstrike", pcapfs::CobaltStrikeFile::create, pcapfs::CobaltStrikeFile::parse);




std::vector<pcapfs::FilePtr> pcapfs::CsUploadedFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx;
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);
    if (!filePtr->flags.test(flags::IS_EMBEDDED_FILE) || !CobaltStrikeManager::getInstance().isFirstPartOfUploadedFile(filePtr))
        return resultVector;

    std::shared_ptr<CsUploadedFile> resultPtr = std::make_shared<CsUploadedFile>();
    resultPtr->setOffsetType(filePtr->getFiletype());
    resultPtr->setFiletype("cs_uploadedfile");
    resultPtr->setTimestamp(filePtr->getTimestamp());
    resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    resultPtr->setProperty("protocol", "cobaltstrike");
    resultPtr->setProperty("domain", filePtr->getProperty("domain"));
    resultPtr->setProperty("uri", filePtr->getProperty("uri"));
    resultPtr->setFilename(filePtr->getFilename());

    std::vector<FilePtr> uploadedFileChunks = CobaltStrikeManager::getInstance().getUploadedFileChunks(filePtr);
    for (const FilePtr &fileChunk : uploadedFileChunks) {
        Fragment fragment;
        fragment.id = fileChunk->getIdInIndex();
        fragment.start = 0;
        fragment.length = fileChunk->getFilesizeProcessed();
        resultPtr->fragments.push_back(fragment);
    }

    resultPtr->setFilesizeRaw(std::accumulate(uploadedFileChunks.begin(), uploadedFileChunks.end(), 0,
                                                [](size_t counter, const FilePtr &file){ return counter + file->getFilesizeProcessed(); }));

    resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());

    resultPtr->flags.set(pcapfs::flags::PROCESSED);
    resultVector.push_back(resultPtr);
    return resultVector;
}


size_t pcapfs::CsUploadedFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf){
    Bytes totalContent;
    for (Fragment fragment: fragments) {
        Bytes rawData(fragment.length);
        FilePtr filePtr = idx.get({offsetType, fragment.id});
        filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
        totalContent.insert(totalContent.end(), rawData.begin(), rawData.end());
    }
    memcpy(buf, totalContent.data() + startOffset, length);
    return std::min(totalContent.size() - startOffset, length);
}


bool pcapfs::CsUploadedFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("cs_uploadedfile", pcapfs::CsUploadedFile::create, pcapfs::CsUploadedFile::parse);