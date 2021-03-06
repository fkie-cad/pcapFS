#include "sslkey.h"

#include <cctype>
#include <fstream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include "../filefactory.h"
#include "../logging.h"
#include "../utils.h"


namespace {
    const char *CLIENT_RANDOM_STRING = "CLIENT_RANDOM";
}


std::vector<pcapfs::FilePtr> pcapfs::SSLKeyFile::parseCandidates(const std::vector<boost::filesystem::path> &keyFiles) {
    std::vector<pcapfs::FilePtr> resultVector;
    //TODO: support multiple SSL key log files, right now only CLIENT_RANDOM <CR> <Master secret>
    for (auto &keyFile: keyFiles) {
        std::ifstream infile(keyFile.string());
        std::string line;
        while (std::getline(infile, line)) {
            std::shared_ptr<SSLKeyFile> keyPtr = std::make_shared<SSLKeyFile>();
            std::vector<std::string> splitInput;
            boost::split(splitInput, line, boost::is_any_of(" "));
            //TODO: check this before?
            if (splitInput.empty()) {
                LOG_ERROR << "empty key file!";
                continue;
            }
            if (splitInput.at(0) == CLIENT_RANDOM_STRING) {
                keyPtr->clientRandom = utils::hexStringToBytes(splitInput.at(1));
                keyPtr->masterSecret = utils::hexStringToBytes(splitInput.at(2));
                keyPtr->setFiletype("sslkey");
            }
            resultVector.push_back(keyPtr);
        }
    }
    return resultVector;
}


std::shared_ptr<pcapfs::SSLKeyFile> pcapfs::SSLKeyFile::createKeyFile(Bytes &keyMaterial) {
    std::shared_ptr<SSLKeyFile> keyPtr = std::make_shared<SSLKeyFile>();
    keyPtr->keyMaterial = keyMaterial;
    keyPtr->setFiletype("sslkey");
    return keyPtr;
}


pcapfs::Bytes pcapfs::SSLKeyFile::getClientWriteKey(uint64_t keySize, uint64_t macSize) {
    if (keyMaterial.size() == 0) {
        return pcapfs::Bytes();
    }

    pcapfs::Bytes clientWriteKey(keySize);
    unsigned int clientWriteKeyOffset = 2 * macSize;
    memcpy(clientWriteKey.data(), keyMaterial.data() + clientWriteKeyOffset, keySize);
    return clientWriteKey;
}


pcapfs::Bytes pcapfs::SSLKeyFile::getServerWriteKey(uint64_t keySize, uint64_t macSize) {
    if (keyMaterial.size() == 0) {
        return pcapfs::Bytes();
    }

    pcapfs::Bytes serverWriteKey(keySize);
    unsigned int serverWriteKeyOffset = 2 * macSize + keySize;
    memcpy(serverWriteKey.data(), keyMaterial.data() + serverWriteKeyOffset, keySize);
    return serverWriteKey;
}


void pcapfs::SSLKeyFile::serialize(boost::archive::text_oarchive &archive) {
    File::serialize(archive);
    archive << keyMaterial;
}


void pcapfs::SSLKeyFile::deserialize(boost::archive::text_iarchive &archive) {
    File::deserialize(archive);
    archive >> keyMaterial;
}


bool pcapfs::SSLKeyFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("sslkey", pcapfs::SSLKeyFile::create);
