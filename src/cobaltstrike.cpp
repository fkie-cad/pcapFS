#include "cobaltstrike.h"

#include <boost/beast/core/detail/base64.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <endian.h>
#include <sstream>
#include "crypto/cryptutils.h"
#include "cobaltstrike/cs_callback_codes.h"
#include "cobaltstrike/cs_command_codes.h"

void pcapfs::CobaltStrike::handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort) {

    if (isKnownConnection(dstIp, dstPort) || cookie.length() <= 34)
        // when the cookie is shorter than 34 characters, the raw key can't be encoded in it
        return;

    LOG_TRACE << "HTTP Header Cookie: " << cookie;
    LOG_TRACE << "check if cookie belongs to cobalt strike";

    Bytes toDecrypt(3*(cookie.length()/4) - 1); // TODO: change size of toDecrypt?
    boost::beast::detail::base64::decode(toDecrypt.data(), cookie.c_str(), cookie.length());

    Bytes result(toDecrypt.size());
    for(const std::string &privKey : privKeyCandidates) {
        result = crypto::rsaPrivateDecrypt(toDecrypt, Bytes(privKey.begin(), privKey.end()), false);
        if (!result.empty()) {

            if (matchMagicBytes(result)) {
                LOG_INFO << "found cobalt strike communication";
                // extract symmetric key material
                Bytes rawKey(result.begin()+8, result.begin()+8+16);
                addConnectionData(rawKey, dstIp, dstPort);
            }
        }
    }
}


bool pcapfs::CobaltStrike::isKnownConnection(const std::string &ServerIp, const std::string &ServerPort) {
    return std::any_of(connections.begin(), connections.end(),
                        [ServerIp,ServerPort](const CobaltStrikeConnectionPtr &conn){ return conn->identifier() == std::make_pair(ServerIp, ServerPort); });
}


bool pcapfs::CobaltStrike::matchMagicBytes(const Bytes& input) {
    const Bytes magicBytes = {0x00, 0x00, 0xbe, 0xef};
    for (int i = 0; i < 4; ++i) {
        if (input[i] != magicBytes [i])
            return false;
    }
    return true;
}


void pcapfs::CobaltStrike::addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort) {
    Bytes digest = crypto::calculateSha256(rawKey);
    if (digest.empty())
        return;

    CobaltStrikeConnectionPtr newConnection = std::make_shared<CobaltStrikeConnection>();
    newConnection->aesKey = Bytes(digest.begin(), digest.begin()+16);
    newConnection->hmacKey = Bytes(digest.begin()+16, digest.end());
    newConnection->serverIp = dstIp;
    newConnection->serverPort = dstPort;
    connections.push_back(newConnection);
}


pcapfs::CobaltStrikeConnectionPtr pcapfs::CobaltStrike::getConnectionData(const std::string &serverIp, const std::string &serverPort) {
    CobaltStrikeConnectionPtr result;
    auto it = std::find_if(connections.cbegin(), connections.cend(),
                         [serverIp,serverPort](const CobaltStrikeConnectionPtr &conn){ return conn->identifier() == std::make_pair(serverIp, serverPort); });
    if (it != connections.cend())
        result = *it;
    return result;
}

// bool: true if server command has embedded file to extract as extra http file
bool pcapfs::CobaltStrike::decryptPayload(const Bytes &input, Bytes &output, const Bytes &aesKey, bool fromClient) {
    if (input.size() < 32 || aesKey.empty()) {
        output.assign(input.begin(), input.end());
        return false;
    }

    Bytes decryptedData, dataToDecrypt;
    if (fromClient) {
        decryptedData.resize(input.size() - 20);
        dataToDecrypt.assign(input.begin()+4, input.end()-16);
    } else {
        decryptedData.resize(input.size() - 16);
        dataToDecrypt.assign(input.begin(), input.end()-16);
    }

    if (opensslDecryptCS(dataToDecrypt, aesKey, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        output.assign(input.begin(), input.end());
        return false;
    }

    if (fromClient) {
        output = parseDecryptedClientContent(decryptedData);
        return false;
    } else {
        return parseDecryptedServerContent(decryptedData, output);

    }
}


int pcapfs::CobaltStrike::opensslDecryptCS(const Bytes &dataToDecrypt, const Bytes &aesKey, Bytes &decryptedData) {

    int error = 0;
    // From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() failed" << std::endl;
        error = 1;
    }
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, aesKey.data(), (const unsigned char*) "abcdefghijklmnop", 0) != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() failed" << std::endl;
        error = 1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, aesKey.data(), (const unsigned char*) "abcdefghijklmnop") != 1) {
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


pcapfs::Bytes const pcapfs::CobaltStrike::parseDecryptedClientContent(const Bytes &data) {
    Bytes result;
    Bytes temp(data.begin(), data.end());
    uint32_t counter = be32toh(*((uint32_t*) temp.data()));
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
        Bytes weirdPayload(std::find_if(zero_it, temp.end(), [](unsigned char c){ return c != 0x00; }), temp.end());
        if (weirdPayload.back() == 0x00)
            weirdPayload.erase(std::find_if(weirdPayload.rbegin(), weirdPayload.rend(), [](unsigned char c){ return c != 0x00; }).base(), weirdPayload.end());
        result.insert(result.end(), metadata.begin(), metadata.end());
        result.insert(result.end(), weirdPayload.begin(), weirdPayload.end());

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


bool pcapfs::CobaltStrike::parseDecryptedServerContent(const Bytes &data, Bytes &output) {
    Bytes temp(data.begin(), data.end());

    bool result = false;
    const uint32_t timestamp_raw = be32toh(*((uint32_t*) temp.data()));
    const uint32_t data_size = be32toh(*((uint32_t*) (temp.data()+4)));
    std::stringstream ss;
    ss << "Timestamp: " << timestamp_raw << "\nData Size: " << data_size;

    const std::string header = ss.str();
    output.insert(output.end(), header.begin(), header.end());

    temp.erase(temp.begin(), temp.begin()+8);

    uint32_t curr_len = 8; // header size with timestamp and data_size
    while (curr_len <= data_size) {
        ss.str("");
        ss << "\n---------------------------------------------------------\n";

        uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) { // we have probably no command content
            output.assign(data.begin(), data.end());
            return false;
        }
        std::string command = CSCommands::codes[command_code];
        uint32_t args_len = be32toh(*((uint32_t*) (temp.data()+4)));
        ss << "Command: " << command_code << " " << command
            << "\nArgs Len: " << args_len << std::endl;

        temp.erase(temp.begin(), temp.begin()+8);
        if (args_len + 8 > data_size)
            break;

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

        } else if (command != "COMMAND_SPAWN_TOKEN_X86" && command != "COMMAND_UPLOAD"){
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());
            output.insert(output.end(), temp.begin(), temp.begin()+args_len);
        } else {
            const std::string params = ss.str();
            output.insert(output.end(), params.begin(), params.end());
        }

        if (command == "COMMAND_SPAWN_TOKEN_X86" || command == "COMMAND_UPLOAD")
            result = true;

        curr_len += args_len + 8;
        temp.erase(temp.begin(), temp.begin()+args_len);

    }

    return result;
 }


 pcapfs::Bytes const pcapfs::CobaltStrike::decryptEmbeddedFile(const Bytes &input, const Bytes &aesKey) {
    if (input.size() < 32 || aesKey.empty())
        return input;

    Bytes decryptedData(input.size() - 16);
    Bytes dataToDecrypt(input.begin(), input.end() - 16);

    if (opensslDecryptCS(dataToDecrypt, aesKey, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        return input;
    }

    Bytes temp(decryptedData.begin(), decryptedData.end());

    const uint32_t data_size = be32toh(*((uint32_t*) (temp.data()+4)));
    temp.erase(temp.begin(), temp.begin()+8);

    uint32_t curr_len = 8; // header size with timestamp and data_size
    while (curr_len < data_size) {

        uint32_t command_code = be32toh(*((uint32_t*) (temp.data())));
        if (command_code > 102) { // we have probably no command content
            return decryptedData;
        }
        std::string command = CSCommands::codes[command_code];
        uint32_t args_len = be32toh(*((uint32_t*) (temp.data()+4)));

        temp.erase(temp.begin(), temp.begin()+8);
        if (args_len + 8 > data_size)
            break;

        if (command == "COMMAND_SPAWN_TOKEN_X86"){
            return Bytes(temp.begin(), temp.begin()+args_len);
        } else if (command == "COMMAND_UPLOAD") {
            return Bytes(temp.begin()+4, temp.begin()+args_len);
        }
        curr_len += args_len + 8;
        temp.erase(temp.begin(), temp.begin()+args_len);
    }
    return decryptedData;
 }
