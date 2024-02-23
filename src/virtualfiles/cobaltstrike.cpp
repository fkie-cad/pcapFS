#include "cobaltstrike.h"
#include "../filefactory.h"
#include "../logging.h"
#include "../exceptions.h"
#include "cobaltstrike/cs_manager.h"
#include "cobaltstrike/cs_callback_codes.h"
#include "cobaltstrike/cs_command_codes.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <endian.h>
#include <sstream>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <regex>
#include <numeric>


std::vector<pcapfs::FilePtr> pcapfs::CobaltStrikeFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx; // prevent unused variable warning
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);
    if (!meetsParsingRequirements(filePtr)) {
        return resultVector;
    }

    LOG_DEBUG << "begin to parse http file regarding cobalt strike";
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

    std::stringstream ss;
    ss << std::chrono::duration_cast<std::chrono::milliseconds>(filePtr->getTimestamp().time_since_epoch()).count();
    const std::string timestamp = ss.str();

    if (isHttpPost(filePtr->getFilename())) {
        const CobaltStrikeConnectionPtr connData = CobaltStrikeManager::getInstance().getConnectionData(
                                                    filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"), filePtr->getProperty("srcIP"));
        resultPtr->cobaltStrikeKeys = connData->aesKeys;
        resultPtr->setFilename(timestamp + "-response");
        resultPtr->fromClient = true;
        const CsContentInfoPtr contentInfo = resultPtr->extractClientContent(data);
        resultPtr->setFilesizeProcessed(contentInfo->filesize);

        for (const auto &embeddedFileInfo : contentInfo->embeddedFileInfos) {
            LOG_DEBUG << "handle embedded file in cobalt strike callback";
            std::shared_ptr<CobaltStrikeFile> embeddedFilePtr = std::make_shared<CobaltStrikeFile>();
            Fragment embeddedFragment;
            embeddedFragment.id = filePtr->getIdInIndex();
            embeddedFragment.start = 0;
            embeddedFragment.length = fragment.length;
            embeddedFilePtr->fragments.push_back(embeddedFragment);

            fillEmbeddedFileProperties(embeddedFilePtr, filePtr, embeddedFileInfo);
            std::string filename = embeddedFileInfo->filename;
            if (filename.find("\\") != std::string::npos) {
                // cut off path to file
                std::vector<std::string> tokens;
                boost::split(tokens, filename, [](char c) { return c == 0x5C; });
                filename = tokens.back();
            }
            embeddedFilePtr->setFilename(resultPtr->getFilename()  + "_" + filename);

            embeddedFilePtr->cobaltStrikeKeys = connData->aesKeys;
            embeddedFilePtr->fromClient = true;

            resultVector.push_back(embeddedFilePtr);
        }

        resultPtr->flags.set(pcapfs::flags::PROCESSED);
        resultVector.push_back(resultPtr);


    } else if (isHttpResponse(filePtr->getFilename())) {
        const CobaltStrikeConnectionPtr connData = CobaltStrikeManager::getInstance().getConnectionData(
                                                    filePtr->getProperty("srcIP"), filePtr->getProperty("srcPort"), filePtr->getProperty("dstIP"));
        resultPtr->cobaltStrikeKeys = connData->aesKeys;
        resultPtr->fromClient = false;

        CsContentInfoPtr contentInfo;
        try {
            contentInfo = resultPtr->extractServerContent(data);
        } catch (PcapFsException &err) {
            // this might be a beacon config file
            LOG_INFO << "found cobalt strike server payload which does not have a valid format to be a command";
            LOG_INFO << "=> we assume this is a beacon config file";
            resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());
            resultPtr->setFilename(timestamp + "-beaconconfig");
            resultPtr->flags.set(pcapfs::flags::PROCESSED);
            resultVector.push_back(resultPtr);
            return resultVector;
        }

        resultPtr->setFilesizeProcessed(contentInfo->filesize);
        resultPtr->setFilename(timestamp + "-" + contentInfo->command);

        for (const auto &embeddedFileInfo : contentInfo->embeddedFileInfos) {
            LOG_DEBUG << "handle embedded file in cobalt strike command";
            std::shared_ptr<CobaltStrikeFile> embeddedFilePtr = std::make_shared<CobaltStrikeFile>();
            Fragment embeddedFragment;
            embeddedFragment.id = filePtr->getIdInIndex();
            embeddedFragment.start = 0;
            embeddedFragment.length = fragment.length;
            embeddedFilePtr->fragments.push_back(embeddedFragment);

            fillEmbeddedFileProperties(embeddedFilePtr, filePtr, embeddedFileInfo);

            if (!embeddedFileInfo->filename.empty()) {
                std::string filename = embeddedFileInfo->filename;
                if (filename.find("\\") != std::string::npos) {
                    // cut off path to file
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

            embeddedFilePtr->cobaltStrikeKeys = connData->aesKeys;
            embeddedFilePtr->fromClient = false;

            const std::string embeddedFileCommand = embeddedFileInfo->command;
            // remember the filePtr of uploaded file chunks for later defragmentation
            if (embeddedFileCommand == "COMMAND_UPLOAD") {
                CobaltStrikeManager::getInstance().addFilePtrToUploadedFiles(embeddedFileInfo->filename, embeddedFilePtr, true);
                embeddedFilePtr->flags.set(pcapfs::flags::CS_DO_NOT_SHOW);

            } else if (embeddedFileCommand == "COMMAND_UPLOAD_CONTINUE") {
                LOG_DEBUG << "noticed fragmented file upload";
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


bool pcapfs::CobaltStrikeFile::meetsParsingRequirements(const FilePtr &filePtr) {
    return (filePtr->getFiletype() == "http" && !filePtr->flags.test(pcapfs::flags::IS_METADATA) &&
        (CobaltStrikeManager::getInstance().isKnownConnection(filePtr->getProperty("dstIP"),
                                    filePtr->getProperty("dstPort"), filePtr->getProperty("srcIP")) ||
        CobaltStrikeManager::getInstance().isKnownConnection(filePtr->getProperty("srcIP"),
                                    filePtr->getProperty("srcPort"), filePtr->getProperty("dstIP"))));
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


void pcapfs::CobaltStrikeFile::fillEmbeddedFileProperties(CobaltStrikeFilePtr &embeddedFilePtr, const FilePtr &filePtr,
                                        const EmbeddedFileInfoPtr &embeddedFileInfo) {

    embeddedFilePtr->setFilesizeRaw(embeddedFileInfo->size);
    embeddedFilePtr->setFilesizeProcessed(embeddedFileInfo->size);
    embeddedFilePtr->embeddedFileIndex = embeddedFileInfo->id;
    embeddedFilePtr->setOffsetType(filePtr->getFiletype());
    embeddedFilePtr->setFiletype("cobaltstrike");
    embeddedFilePtr->setTimestamp(filePtr->getTimestamp());
    embeddedFilePtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
    embeddedFilePtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
    embeddedFilePtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
    embeddedFilePtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
    embeddedFilePtr->setProperty("domain", filePtr->getProperty("domain"));
    embeddedFilePtr->setProperty("uri", filePtr->getProperty("uri"));
    embeddedFilePtr->setProperty("protocol", "cobaltstrike");
    embeddedFilePtr->flags.set(pcapfs::flags::IS_EMBEDDED_FILE);
    embeddedFilePtr->flags.set(pcapfs::flags::PROCESSED);
}


pcapfs::CsContentInfoPtr const pcapfs::CobaltStrikeFile::extractClientContent(const Bytes &input) {
    LOG_DEBUG << "extract content information from cobalt strike callback";
    const std::string SEP_LINE = "\n---------------------------------------------------------\n";
    CsContentInfoPtr result = std::make_shared<CsContentInfo>();
    result->filesize = input.size();

    const std::vector<Bytes> decryptedChunks = decryptClientPayload(input);
    if (decryptedChunks.empty())
        return result;

    Bytes parsedData;
    uint64_t currIndex = 0;
    uint32_t filesize = 0;
    std::string filename;
    for (const Bytes &decryptedChunk : decryptedChunks) {

        const uint32_t counter = be32toh(*((uint32_t*) (decryptedChunk.data())));
        const uint32_t data_size = be32toh(*((uint32_t*) (decryptedChunk.data()+4)));
        if (data_size > decryptedChunk.size()) {
            LOG_DEBUG << "parsed length of decrypted client message is invalid";
            return result;
        }
        const uint32_t callback_code = be32toh(*((uint32_t*) (decryptedChunk.data()+8)));
        const std::string callback_string = callback_code < 33 ? CSCallback::codes[callback_code] : "CALLBACK_UNKNOWN";
        LOG_DEBUG << "current callback: " << callback_string;

        std::stringstream ss;
        ss << "Counter: " << counter << "\nCallback: " << callback_code << " " << callback_string << "\n\n";

        const std::string metadata = ss.str();
        parsedData.insert(parsedData.end(), metadata.begin(), metadata.end());

        if (callback_string == "CALLBACK_PENDING") {
            // CALLBACK_PENDING payload starts 4 bytes later
            parsedData.insert(parsedData.end(), decryptedChunk.begin()+16, decryptedChunk.begin()+data_size+8);
        } else if (callback_string == "CALLBACK_ERROR") {
            ss.str("");
            // these arguments are numbers which may give further error information
            ss << "Argument: " << be32toh(*((uint32_t*) (decryptedChunk.data()+12))) << "\nArgument: "
                << be32toh(*((uint32_t*) (decryptedChunk.data()+16)));
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());
        } else if (callback_string == "CALLBACK_SCREENSHOT") {
            EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->filename = "screenshot";
            const size_t jpg_eof = getEndOfJpgFile(decryptedChunk);
            if (jpg_eof != 0) {
                const Bytes additional_chunk(decryptedChunk.begin()+jpg_eof+4, decryptedChunk.end());
                const uint32_t arg_size1 = le32toh(*((uint32_t*) additional_chunk.data()));
                if (arg_size1 > additional_chunk.size() - 4)
                    continue;
                ss.str("");
                ss << "Argument: " << std::string(additional_chunk.begin()+4, additional_chunk.begin()+4+arg_size1);
                const uint32_t arg_size2 = le32toh(*((uint32_t*) (additional_chunk.data()+4+arg_size1)));
                if (arg_size2 > additional_chunk.size() - 8 - arg_size1)
                    continue;
                ss << "\nArgument: " << std::string(additional_chunk.begin()+8+arg_size1, additional_chunk.begin()+8+arg_size1+arg_size2);
                const std::string params = ss.str();
                parsedData.insert(parsedData.end(), params.begin(), params.end());

                embeddedFileInfo->size = jpg_eof - 16;
                result->embeddedFileInfos.push_back(embeddedFileInfo);
            } else {
                LOG_DEBUG << "did not find end of screenshot file";
                embeddedFileInfo->size = decryptedChunk.size() - 16;
                result->embeddedFileInfos.push_back(embeddedFileInfo);
            }

        } else if (callback_string == "CALLBACK_FILE") {
            ss.str("");
            filesize = be32toh(*((uint32_t*) (decryptedChunk.data()+16)));
            ss << "File Size: " << filesize;
            filename.assign(decryptedChunk.begin()+20, decryptedChunk.begin()+data_size+8);
            ss << "\nFile: " << filename;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (callback_string == "CALLBACK_FILE_WRITE" && filesize == data_size - 8) {
            EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->size = filesize;
            embeddedFileInfo->filename = filename;
            result->embeddedFileInfos.push_back(embeddedFileInfo);

        } else if (callback_string == "CALLBACK_KEYSTROKES") {
            Bytes keystrokesChunk(decryptedChunk.begin()+12, decryptedChunk.end());
            const uint32_t keystrokes_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (keystrokes_len > keystrokesChunk.size() - 4)
                continue;
            const std::string keystrokes = handleKeystrokes(std::string(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+keystrokes_len));
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4+keystrokes_len);
            const uint32_t session = le32toh(*((uint32_t*) keystrokesChunk.data()));
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4);
            const uint32_t title_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (title_len > keystrokesChunk.size() - 4)
                continue;
            const std::string title(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+title_len);
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4+title_len);
            const uint32_t user_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (user_len > keystrokesChunk.size() - 4)
                continue;
            const std::string user(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+user_len);
            ss.str("");
            ss << "User: " << user << "\nSession: " << session << "\nTitle: " << title << "\nKeystrokes:\n" << keystrokes;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else {
            parsedData.insert(parsedData.end(), decryptedChunk.begin()+12, decryptedChunk.begin()+data_size+8);
        }
        parsedData.insert(parsedData.end(), SEP_LINE.begin(), SEP_LINE.end());
        currIndex++;
    }

    LOG_DEBUG << "extracted content information from cobalt strike callback successfully";
    result->filesize = parsedData.size();
    return result;
}


std::string const pcapfs::CobaltStrikeFile::handleKeystrokes(const std::string& input) {
    std::string result;
    try {
        result = std::regex_replace(input, std::regex("\x03[A-Z0-9]|\x0f"), "");
    } catch (std::regex_error &err) {
        return input;
    }
    return result;
}


pcapfs::CsContentInfoPtr const pcapfs::CobaltStrikeFile::extractServerContent(const Bytes &input) {
    LOG_DEBUG << "extract content information from cobalt strike command";
    CsContentInfoPtr result = std::make_shared<CsContentInfo>();
    result->filesize = input.size();

    const Bytes decryptedData = decryptServerPayload(input);
    if (decryptedData.empty())
        return result;

    Bytes parsedData;
    Bytes temp(decryptedData.begin(), decryptedData.end());

    const time_t timestamp = be32toh(*((uint32_t*) temp.data()));
    const uint32_t data_size = be32toh(*((uint32_t*) (temp.data()+4)));
    if (data_size > input.size()) {
        // this exception is to indicate that this may be a beacon config file
        throw PcapFsException("parsed length of server message is invalid");
    }

    std::stringstream ss;
    ss << "Timestamp: " << std::put_time(std::localtime(&timestamp), "%Y-%m-%d %I:%M:%S %p")
        << "\nData Size: " << data_size;
    const std::string header = ss.str();
    parsedData.insert(parsedData.end(), header.begin(), header.end());

    temp.erase(temp.begin(), temp.begin()+8);
    uint32_t currOffset = 8; // header size with timestamp and data_size
    for (uint64_t currIndex = 0; currOffset <= data_size; ++currIndex) {
        ss.str("");
        ss << "\n---------------------------------------------------------\n";

        const uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) {
            // we have probably no command content
            LOG_DEBUG << "the parsed command code is not known";
            return result;
        }
        const std::string command = CSCommands::codes.at(command_code);
        LOG_DEBUG << "current command: " << command;
        if (currIndex == 0)
            result->command = extractServerCommand(command);

        const uint32_t args_len = be32toh(*((uint32_t*) (temp.data()+4)));
        if (args_len + 8 > temp.size()) {
            LOG_DEBUG << "the parsed argument length is invalid";
            return result;
        }
        ss << "Command: " << command_code << " " << command
            << "\nArgs Len: " << args_len << std::endl;
        temp.erase(temp.begin(), temp.begin()+8);

        if (command == "COMMAND_LS") {
            const uint32_t ls_counter = be32toh(*((uint32_t*) temp.data()));
            //uint32_t ls_dir_len = be32toh(*((uint32_t*) (ls_params+4)));
            const std::string ls_dir(temp.begin()+8, temp.begin()+args_len);
            ss << "Counter: " << ls_counter <<  "\nDirectory: " << ls_dir;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_CD") {
            const std::string dir(temp.begin(), temp.begin()+args_len);
            ss << "Directory: " << dir;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_RM"){
            const std::string file(temp.begin(), temp.begin()+args_len);
            ss << "File: " << file;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_SLEEP") {
            const uint32_t sleep = be32toh(*((uint32_t*) temp.data()));
            const uint32_t jitter = be32toh(*((uint32_t*) (temp.data()+4)));
            ss << "Sleep: " << sleep << "\nJitter: " << jitter;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_GETPRIVS") {
            Bytes privPayload(temp.begin(), temp.begin()+args_len);
            const uint16_t numPrivs = be16toh(*((uint16_t*) privPayload.data()));
            privPayload.erase(privPayload.begin(), privPayload.begin()+2);
            ss << "Privileges:\n";
            uint32_t currPrivLen;
            std::string currPriv;
            for (uint16_t i = 0; i < numPrivs; ++i) {
                currPrivLen = be32toh(*((uint32_t*) privPayload.data()));
                if (currPrivLen > privPayload.size() - 4)
                    break;
                currPriv.assign(privPayload.begin()+4, privPayload.begin()+4+currPrivLen);
                ss << currPriv << std::endl;
                privPayload.erase(privPayload.begin(), privPayload.begin()+4+currPrivLen);
            }
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_MAKE_TOKEN") {
            Bytes tokenPayload(temp.begin(), temp.begin()+args_len);
            uint32_t len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return result;
            ss << "Domain: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            tokenPayload.erase(tokenPayload.begin(), tokenPayload.begin()+4+len);
            len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return result;
            ss << "\nUser: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            tokenPayload.erase(tokenPayload.begin(), tokenPayload.begin()+4+len);
            len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return result;
            ss << "\nPassword: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_EXECUTE_JOB") {
            const size_t args_len_without_padding = getLengthWithoutPadding(temp, args_len);
            size_t currPos = 0;
            while (currPos < args_len_without_padding) {
                const uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len_without_padding - currPos) {
                    // parsed argument length is invalid
                    return result;
                }
                const std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_JOB_REGISTER" || command == "COMMAND_JOB_REGISTER_MSGMODE") {
            size_t currPos = 8; // we have 2 unknown additional fields in front
            while (currPos < args_len) {
                const uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len - currPos) {
                    // parsed argument length is invalid
                    return result;
                }
                //std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                const std::string argument(temp.begin()+4+currPos, std::find_if(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen,
                                                                        [](unsigned char c){ return c == 0x00; }));
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else if (command == "COMMAND_UPLOAD" || command == "COMMAND_UPLOAD_CONTINUE") {
            const uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
            if (filenameLen > args_len)
                return result;

            const std::string filename(temp.begin()+4, temp.begin()+4+filenameLen);
            ss << "File: " << filename;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

            EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->filename = filename;
            embeddedFileInfo->size = args_len - 4 - filenameLen;
            embeddedFileInfo->isChunk = (command == "COMMAND_UPLOAD_CONTINUE");
            result->embeddedFileInfos.push_back(embeddedFileInfo);

        } else if (command == "COMMAND_SPAWN_TOKEN_X86" || command == "COMMAND_SPAWN_TOKEN_X64" ||
                command == "COMMAND_SPAWNX64" || command == "COMMAND_INLINE_EXECUTE_OBJECT") {
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

            EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->size = args_len;
            result->embeddedFileInfos.push_back(embeddedFileInfo);

        } else if (command == "COMMAND_INJECT_PID" || command == "COMMAND_INJECTX64_PID") {
            const uint32_t pid = be32toh(*((uint32_t*) temp.data()));
            ss << "PID: " << pid;
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

            EmbeddedFileInfoPtr embeddedFileInfo = std::make_shared<CsEmbeddedFileInfo>();
            embeddedFileInfo->id = currIndex;
            embeddedFileInfo->command = command;
            embeddedFileInfo->size = args_len - 8;
            result->embeddedFileInfos.push_back(embeddedFileInfo);

        } else if (args_len == 4) {
            if (command == "COMMAND_KILL" || command == "COMMAND_STEALTOKEN")
                ss << "PID: " << be32toh(*((uint32_t*) temp.data()));
            else
                ss << "Argument: " << be32toh(*((uint32_t*) temp.data()));
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());

        } else {
            const std::string params = ss.str();
            parsedData.insert(parsedData.end(), params.begin(), params.end());
            parsedData.insert(parsedData.end(), temp.begin(), temp.begin()+args_len);
        }
        currOffset += args_len + 8;
        temp.erase(temp.begin(), temp.begin()+args_len);
    }

    LOG_DEBUG << "extracted content information from cobalt strike command successfully";
    result->filesize = parsedData.size();
    return result;
}


std::vector<pcapfs::Bytes>  const pcapfs::CobaltStrikeFile::decryptClientPayload(const Bytes &input) {
    LOG_DEBUG << "decrypt cobalt strike client payload";
    if (input.size() < 32 || cobaltStrikeKeys.empty()) {
        LOG_DEBUG << "decryption requirements are not met";
        return std::vector<Bytes>(0);
    }
    std::vector<Bytes> decryptedChunks(0);
    Bytes temp = input;
    uint32_t currLen = 0;
    while (currLen < input.size()) {
        const uint32_t chunkLen = be32toh(*((uint32_t*) (temp.data())));
        if (chunkLen > input.size() || chunkLen < 16) {
            LOG_ERROR << "cobalt strike: parsed length of encrypted client message is invalid";
            return std::vector<Bytes>(0);
        }
        temp.erase(temp.begin(), temp.begin()+4);
        const Bytes encryptedChunk(temp.begin(), temp.begin()+chunkLen - 16); // exclude hmac
        Bytes decryptedChunk(chunkLen - 16);

        for (const Bytes &keyCandidate : cobaltStrikeKeys) {
            if (opensslDecryptCS(encryptedChunk, decryptedChunk, keyCandidate)) {
                LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
                return std::vector<Bytes>(0);
            }
            const uint32_t data_size = be32toh(*((uint32_t*) (decryptedChunk.data()+4)));
            if (data_size > decryptedChunk.size()) {
                // decryption probably with wrong key, try next key if possible;
                if (keyCandidate == cobaltStrikeKeys.back()) {
                    // no key worked
                    return std::vector<Bytes>(0);
                } else {
                    decryptedChunk.clear();
                    decryptedChunk.resize(chunkLen - 16);
                    continue;
                }
            } else
                break;
        }

        decryptedChunks.push_back(decryptedChunk);
        currLen += chunkLen + 4; // plus field of chunkLen
        temp.erase(temp.begin(), temp.begin()+chunkLen);
    }

    return decryptedChunks;
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::decryptServerPayload(const Bytes &input) {
    LOG_DEBUG << "decrypt cobalt strike server payload";
    if (input.size() < 32 || cobaltStrikeKeys.empty()) {
        LOG_DEBUG << "decryption requirements are not met";
        return Bytes();
    }
    const Bytes dataToDecrypt(input.begin(), input.end() - 16); // exclude hmac
    Bytes decryptedData(input.size() - 16);
    for (const Bytes &keyCandidate : cobaltStrikeKeys) {
        if (opensslDecryptCS(dataToDecrypt, decryptedData, keyCandidate)) {
            LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
            return Bytes();
        }
        const uint32_t data_size = be32toh(*((uint32_t*) (decryptedData.data()+4)));
        if (data_size > decryptedData.size()) {
            // decryption probably with wrong key, try next key if possible;
            if (keyCandidate == cobaltStrikeKeys.back()) {
                // no key worked
                return Bytes();
            } else {
                decryptedData.clear();
                decryptedData.resize(input.size() - 16);
                continue;
            }
        } else
            return decryptedData;
    }
    return Bytes();
}


size_t pcapfs::CobaltStrikeFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));

    Bytes decryptedData;
    if (flags.test(pcapfs::flags::IS_EMBEDDED_FILE))
        decryptedData = fromClient ? readEmbeddedClientFile(rawData): readEmbeddedServerFile(rawData);
    else
        decryptedData = fromClient ? readClientContent(rawData): readServerContent(rawData);

    memcpy(buf, decryptedData.data() + startOffset, length);
    return std::min(decryptedData.size() - startOffset, length);
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::readClientContent(const Bytes &input) {
    LOG_DEBUG << "read cobalt strike client callback(s)";
    const std::string SEP_LINE = "\n---------------------------------------------------------\n";
    Bytes result;
    const std::vector<Bytes> decryptedChunks = decryptClientPayload(input);
    if (decryptedChunks.empty())
        return input;

    for (const Bytes &decryptedChunk : decryptedChunks) {

        const uint32_t counter = be32toh(*((uint32_t*) (decryptedChunk.data())));
        const uint32_t data_size = be32toh(*((uint32_t*) (decryptedChunk.data()+4)));
        if (data_size > decryptedChunk.size()) {
            LOG_INFO << "cobalt strike: parsed length of decrypted client message is invalid";
            return input;
        }
        const uint32_t callback_code = be32toh(*((uint32_t*) (decryptedChunk.data()+8)));
        const std::string callback_string = callback_code < 33 ? CSCallback::codes.at(callback_code) : "CALLBACK_UNKNOWN";

        std::stringstream ss;
        ss << "Counter: " << counter << "\nCallback: " << callback_code << " " << callback_string << "\n\n";
        const std::string metadata = ss.str();
        result.insert(result.end(), metadata.begin(), metadata.end());

        if (callback_string == "CALLBACK_PENDING") {
            // CALLBACK_PENDING payload starts 4 bytes later
            result.insert(result.end(), decryptedChunk.begin()+16, decryptedChunk.begin()+data_size+8);
        } else if (callback_string == "CALLBACK_ERROR") {
            ss.str("");
            // these arguments are numbers which maybe indicate further error information
            ss << "Argument: " << be32toh(*((uint32_t*) (decryptedChunk.data()+12))) << "\nArgument: "
                << be32toh(*((uint32_t*) (decryptedChunk.data()+16)));
            const std::string params = ss.str();
            result.insert(result.end(), params.begin(), params.end());
        } else if (callback_string == "CALLBACK_SCREENSHOT") {
            const size_t jpg_eof = getEndOfJpgFile(decryptedChunk);
            if (jpg_eof != 0) {
                const Bytes additional_chunk(decryptedChunk.begin()+jpg_eof+4, decryptedChunk.end());
                const uint32_t arg_size1 = le32toh(*((uint32_t*) additional_chunk.data()));
                if (arg_size1 > additional_chunk.size() - 4)
                    continue;
                ss.str("");
                ss << "Argument: " << std::string(additional_chunk.begin()+4, additional_chunk.begin()+4+arg_size1);
                const uint32_t arg_size2 = le32toh(*((uint32_t*) (additional_chunk.data()+4+arg_size1)));
                if (arg_size2 > additional_chunk.size() - 8 - arg_size1)
                    continue;
                ss << "\nArgument: " << std::string(additional_chunk.begin()+8+arg_size1, additional_chunk.begin()+8+arg_size1+arg_size2);
                const std::string params = ss.str();
                result.insert(result.end(), params.begin(), params.end());
            }

        } else if (callback_string == "CALLBACK_FILE") {
            ss.str("");
            const uint32_t filesize = be32toh(*((uint32_t*) (decryptedChunk.data()+16)));
            ss << "File Size: " << filesize;
            const std::string filename(decryptedChunk.begin()+20, decryptedChunk.begin()+data_size+8);
            ss << "\nFile: " << filename;
            const std::string params = ss.str();
            result.insert(result.end(), params.begin(), params.end());

        } else if (callback_string == "CALLBACK_KEYSTROKES") {
            Bytes keystrokesChunk(decryptedChunk.begin()+12, decryptedChunk.end());
            const uint32_t keystrokes_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (keystrokes_len > keystrokesChunk.size() - 4)
                continue;
            const std::string keystrokes = handleKeystrokes(std::string(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+keystrokes_len));
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4+keystrokes_len);
            const uint32_t session = le32toh(*((uint32_t*) keystrokesChunk.data()));
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4);
            const uint32_t title_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (title_len > keystrokesChunk.size() - 4)
                continue;
            const std::string title(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+title_len);
            keystrokesChunk.erase(keystrokesChunk.begin(), keystrokesChunk.begin()+4+title_len);
            const uint32_t user_len = le32toh(*((uint32_t*) keystrokesChunk.data()));
            if (user_len > keystrokesChunk.size() - 4)
                continue;
            const std::string user(keystrokesChunk.begin()+4, keystrokesChunk.begin()+4+user_len);
            ss.str("");
            ss << "User: " << user << "\nSession: " << session << "\nTitle: " << title << "\nKeystrokes:\n" << keystrokes;
            const std::string params = ss.str();
            result.insert(result.end(), params.begin(), params.end());

        } else if (callback_string != "CALLBACK_FILE_WRITE") {
            result.insert(result.end(), decryptedChunk.begin()+12, decryptedChunk.begin()+data_size+8);
        }

        result.insert(result.end(), SEP_LINE.begin(), SEP_LINE.end());
    }

    return result;
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::readServerContent(const Bytes &input) {
    LOG_DEBUG << "read cobalt strike server command(s)";
    const Bytes data = decryptServerPayload(input);
    if (data.empty())
        return input;

    Bytes temp(data.begin(), data.end());
    Bytes output;

    const time_t timestamp = be32toh(*((uint32_t*) temp.data()));
    const uint32_t data_size = be32toh(*((uint32_t*) (temp.data()+4)));
    if (data_size > data.size()) {
        //LOG_INFO << "cobalt strike: parsed length of server message is invalid";
        return input;
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

        const uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) {
            // we have probably no command content
            LOG_WARNING << "cobalt strike: parsed server command is invalid";
            return input;
        }
        const std::string command = CSCommands::codes.at(command_code);
        const uint32_t args_len = be32toh(*((uint32_t*) (temp.data()+4)));
        if (args_len + 8 > temp.size()) {
            LOG_WARNING << "cobalt strike: parsed argument length of server command is invalid";
            return input;
        }

        ss << "Command: " << command_code << " " << command
            << "\nArgs Len: " << args_len << std::endl;
        temp.erase(temp.begin(), temp.begin()+8);

        if (command == "COMMAND_LS") {
            const uint32_t ls_counter = be32toh(*((uint32_t*) temp.data()));
            //uint32_t ls_dir_len = be32toh(*((uint32_t*) (ls_params+4)));
            const std::string ls_dir(temp.begin()+8, temp.begin()+args_len);
            ss << "Counter: " << ls_counter <<  "\nDirectory: " << ls_dir;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_CD") {
            const std::string dir(temp.begin(), temp.begin()+args_len);
            ss << "Directory: " << dir;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_RM"){
            const std::string file(temp.begin(), temp.begin()+args_len);
            ss << "File: " << file;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_SLEEP") {
            const uint32_t sleep = be32toh(*((uint32_t*) temp.data()));
            const uint32_t jitter = be32toh(*((uint32_t*) (temp.data()+4)));
            ss << "Sleep: " << sleep << "\nJitter: " << jitter;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_GETPRIVS") {
            Bytes privPayload(temp.begin(), temp.begin()+args_len);
            const uint16_t numPrivs = be16toh(*((uint16_t*) privPayload.data()));
            privPayload.erase(privPayload.begin(), privPayload.begin()+2);
            ss << "Privileges:\n";
            uint32_t currPrivLen;
            std::string currPriv;
            for (uint16_t i = 0; i < numPrivs; ++i) {
                currPrivLen = be32toh(*((uint32_t*) privPayload.data()));
                if (currPrivLen > privPayload.size() - 4)
                    break;
                currPriv.assign(privPayload.begin()+4, privPayload.begin()+4+currPrivLen);
                ss << currPriv << std::endl;
                privPayload.erase(privPayload.begin(), privPayload.begin()+4+currPrivLen);
            }
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_MAKE_TOKEN") {
            Bytes tokenPayload(temp.begin(), temp.begin()+args_len);
            uint32_t len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return input;
            ss << "Domain: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            tokenPayload.erase(tokenPayload.begin(), tokenPayload.begin()+4+len);
            len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return input;
            ss << "\nUser: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            tokenPayload.erase(tokenPayload.begin(), tokenPayload.begin()+4+len);
            len = be32toh(*((uint32_t*) tokenPayload.data()));
            if (len > tokenPayload.size() - 4)
                return input;
            ss << "\nPassword: " << std::string(tokenPayload.begin()+4, tokenPayload.begin()+4+len);
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_EXECUTE_JOB") {
            const size_t args_len_without_padding = getLengthWithoutPadding(temp, args_len);
            size_t currPos = 0;
            while (currPos < args_len_without_padding) {
                const uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len_without_padding - currPos) {
                    LOG_WARNING << "cobalt strike: parsed argument length of COMMAND_EXECUTE_JOB is invalid";
                    return input;
                }
                const std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_JOB_REGISTER" || command == "COMMAND_JOB_REGISTER_MSGMODE") {
            size_t currPos = 8; // we have 2 unknown additional fields in front
            while (currPos < args_len) {
                const uint32_t tempLen = be32toh(*((uint32_t*) (temp.data()+currPos)));
                if (tempLen > args_len - currPos) {
                    LOG_WARNING << "cobalt strike: parsed argument length of COMMAND_JOB_REGISTER is invalid";
                    return input;
                }
                //std::string argument(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen);
                const std::string argument(temp.begin()+4+currPos, std::find_if(temp.begin()+4+currPos, temp.begin()+4+currPos+tempLen,
                                                                        [](unsigned char c){ return c == 0x00; }));
                ss << "Argument: " << argument << std::endl;
                currPos += tempLen + 4;
            }
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_UPLOAD" || command == "COMMAND_UPLOAD_CONTINUE") {
            const uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
            if (filenameLen > args_len) {
                LOG_WARNING << "cobalt strike: parsed filename length of upload command is invalid";
                return input;
            }
            const std::string filename(temp.begin()+4, temp.begin()+4+filenameLen);
            ss << "File: " << filename;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_INLINE_EXECUTE_OBJECT" || command == "COMMAND_SPAWN_TOKEN_X86" ||
                    command == "COMMAND_SPAWNX64" || command == "COMMAND_SPAWN_TOKEN_X64") {
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (command == "COMMAND_INJECT_PID" || command == "COMMAND_INJECTX64_PID") {
            const uint32_t pid = be32toh(*((uint32_t*) temp.data()));
            ss <<"PID: " << pid;
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());

        } else if (args_len == 4) {
            if (command == "COMMAND_KILL" || command == "COMMAND_STEALTOKEN")
                ss << "PID: " << be32toh(*((uint32_t*) temp.data()));
            else
                ss << "Argument: " << be32toh(*((uint32_t*) temp.data()));
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


pcapfs::Bytes const pcapfs::CobaltStrikeFile::readEmbeddedClientFile(const Bytes &input) {
    LOG_DEBUG << "read file embedded in cobalt strike client callback(s)";
    std::vector<Bytes> decryptedChunks = decryptClientPayload(input);
    if (decryptedChunks.empty())
        return input;

    Bytes result;
    uint64_t currIndex = 0;
    for (const Bytes &decryptedChunk : decryptedChunks) {
        if (currIndex == embeddedFileIndex) {
            const uint32_t callback_code = be32toh(*((uint32_t*) (decryptedChunk.data()+8)));
            const std::string callback_string = callback_code < 33 ? CSCallback::codes.at(callback_code) : "CALLBACK_UNKNOWN";

            if (callback_string == "CALLBACK_SCREENSHOT") {
                const size_t jpg_eof = getEndOfJpgFile(decryptedChunk);
                if (jpg_eof != 0)
                    result.insert(result.end(), decryptedChunk.begin()+16, decryptedChunk.begin()+jpg_eof);
                else
                    result.insert(result.end(), decryptedChunk.begin()+16, decryptedChunk.end());

            } else if (callback_string == "CALLBACK_FILE_WRITE") {
                const uint32_t data_size = be32toh(*((uint32_t*) (decryptedChunk.data()+4)));
                result.insert(result.end(), decryptedChunk.begin()+16, decryptedChunk.begin()+data_size+8);
            }
        }
        currIndex++;
    }

    return result;
}


pcapfs::Bytes const pcapfs::CobaltStrikeFile::readEmbeddedServerFile(const Bytes &input) {
    LOG_DEBUG << "read file embedded in cobalt strike server command(s)";
    const Bytes decryptedData = decryptServerPayload(input);
    if (decryptedData.empty())
        return input;

    Bytes temp(decryptedData.begin(), decryptedData.end());

    const uint32_t dataSize = be32toh(*((uint32_t*) (temp.data()+4)));
    temp.erase(temp.begin(), temp.begin()+8);

    uint32_t currOffset = 8; // header size with timestamp and data_size
    for (uint64_t currIndex = 0; currOffset < dataSize; ++currIndex) {

        const uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) { // we have probably no command content
            return decryptedData;
        }
        const std::string command = CSCommands::codes.at(command_code);
        const uint32_t argsLen = be32toh(*((uint32_t*) (temp.data()+4)));

        temp.erase(temp.begin(), temp.begin()+8);
        if (argsLen + 8 > dataSize) {
            LOG_WARNING << "cobalt strike: parsed argument length of server command is invalid";
            return input;
        }

        if (currIndex == embeddedFileIndex) {
            if (command == "COMMAND_SPAWN_TOKEN_X86" || command == "COMMAND_SPAWN_TOKEN_X64" ||
                command == "COMMAND_SPAWNX64" || command == "COMMAND_INLINE_EXECUTE_OBJECT"){
                return Bytes(temp.begin(), temp.begin()+argsLen);

            } else if (command == "COMMAND_INJECT_PID" || command == "COMMAND_INJECTX64_PID") {
                return Bytes(temp.begin()+8, temp.begin()+argsLen);

            } else if (command == "COMMAND_UPLOAD" || command == "COMMAND_UPLOAD_CONTINUE") {
                const uint32_t filenameLen = be32toh(*((uint32_t*) temp.data()));
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


int pcapfs::CobaltStrikeFile::opensslDecryptCS(const Bytes &dataToDecrypt, Bytes &decryptedData, const Bytes &aesKey) {

    // we can't use the crypto::opensslDecrypt function because
    // cobalt strike pads in a way that EVP_DecryptFinal doesn't like
    // => we have to unpad manually later on
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR << "Openssl: EVP_CIPHER_CTX_new() failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, aesKey.data(), (const unsigned char*) "abcdefghijklmnop") != 1) {
        LOG_ERROR << "Openssl: EVP_DecryptInit_ex() failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }

    // don't remove padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen;
    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &outlen, dataToDecrypt.data(), dataToDecrypt.size()) != 1) {
        LOG_ERROR << "Openssl: EVP_DecryptUpdate() failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_cleanup(ctx);
        return 1;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    return 0;
}


 size_t pcapfs::CobaltStrikeFile::getEndOfJpgFile(const Bytes &input) {
    for (size_t i = input.size() - 1 ; i > 0; i-= 2) {
        if (input[i] == 0xd9 && input[i-1] == 0xff)
            return i+1;
    }
    return 0;
}


std::string const pcapfs::CobaltStrikeFile::extractServerCommand(const std::string &input) {
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


size_t pcapfs::CobaltStrikeFile::getLengthWithoutPadding(const Bytes &input, uint32_t inputLength) {
    Bytes temp(input.begin(), input.begin()+inputLength);
    temp.erase(std::find_if(temp.rbegin(), temp.rend(), [](unsigned char c){ return c != 0x00; }).base(), temp.end());
    return temp.size();
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
    archive << cobaltStrikeKeys;
    archive << (fromClient ? 1 : 0);
    archive << embeddedFileIndex;

}


void pcapfs::CobaltStrikeFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    int i;
    archive >> cobaltStrikeKeys;
    archive >> i;
    fromClient = i ? true : false;
    archive >> embeddedFileIndex;
}


bool pcapfs::CobaltStrikeFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("cobaltstrike", pcapfs::CobaltStrikeFile::create, pcapfs::CobaltStrikeFile::parse);



/**
 * The virtual file type CsUploadedFile operates on top of the Cobalt Strike layer and defragments uploaded files
 * which are transmitted in multiple chunks.
*/
std::vector<pcapfs::FilePtr> pcapfs::CsUploadedFile::parse(FilePtr filePtr, Index &idx) {
    (void)idx; // prevent unused variable warning
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

    LOG_DEBUG << "defragment cobalt strike file upload";
    const std::vector<FilePtr> uploadedFileChunks = CobaltStrikeManager::getInstance().getUploadedFileChunks(filePtr);
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
    LOG_DEBUG << "read defragmented cobalt strike file upload";
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
