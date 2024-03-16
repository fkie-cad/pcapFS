#include "tlskey.h"

#include <cctype>
#include <fstream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include "../filefactory.h"
#include "../logging.h"
#include "../utils.h"


namespace {
    const char *CLIENT_RANDOM_STRING = "CLIENT_RANDOM";
    const char *RSA_STRING = "RSA";
    const char *RSA_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
}


std::vector<pcapfs::FilePtr> pcapfs::TLSKeyFile::parseCandidates(const std::vector<boost::filesystem::path> &keyFiles) {
    std::vector<pcapfs::FilePtr> resultVector;
    for (auto &keyFile: keyFiles) {
        std::ifstream infile(keyFile.string());
        if (!infile.is_open()) {
            LOG_ERROR << "Failed to open key file " << keyFile.string();
            continue;
        }
        std::string line;
        while (std::getline(infile, line)) {
            std::shared_ptr<TLSKeyFile> keyPtr = std::make_shared<TLSKeyFile>();

            if (line.rfind(RSA_KEY_BEGIN) != std::string::npos) {
                char elem;
                keyPtr->rsaPrivateKey.insert(keyPtr->rsaPrivateKey.end(), RSA_KEY_BEGIN, RSA_KEY_BEGIN+32);
                keyPtr->rsaPrivateKey.push_back(0x0a); // add newline

                while(infile.get(elem)) {
                    keyPtr->rsaPrivateKey.push_back(elem);
                }

                keyPtr->setFiletype("tlskey");
                resultVector.push_back(keyPtr);

            } else {
                keyPtr = extractKeyContent(line);
                if (keyPtr)
                    resultVector.push_back(keyPtr);
            }
        }
    }
    return resultVector;
}


std::shared_ptr<pcapfs::TLSKeyFile> pcapfs::TLSKeyFile::extractKeyContent(const std::string &line) {
    std::shared_ptr<TLSKeyFile> keyPtr = std::make_shared<TLSKeyFile>();
    std::vector<std::string> splitInput;
    boost::split(splitInput, line, boost::is_any_of(" "));
    //TODO: check this before?
    if (splitInput.empty()) {
        LOG_ERROR << "empty key file!";
        return nullptr;
    }
    if (splitInput.at(0) == CLIENT_RANDOM_STRING) {
        try {
            keyPtr->clientRandom = utils::hexStringToBytes(splitInput.at(1));
            keyPtr->masterSecret = utils::hexStringToBytes(splitInput.at(2));
            keyPtr->setFiletype("tlskey");
        } catch (std::out_of_range &e) {
            LOG_ERROR << "invalid key file format of tls key file";
            return nullptr;
        }
    } else if (splitInput.at(0) == RSA_STRING) {
        try {
            keyPtr->rsaIdentifier = utils::hexStringToBytes(splitInput.at(1));
            keyPtr->preMasterSecret = utils::hexStringToBytes(splitInput.at(2));
            keyPtr->setFiletype("tlskey");
        } catch (std::out_of_range &e) {
            LOG_ERROR << "invalid key file format of tls key file";
            return nullptr;
        }
    }

    return keyPtr;
}


std::shared_ptr<pcapfs::TLSKeyFile> pcapfs::TLSKeyFile::createKeyFile(const Bytes &keyMaterial) {
    std::shared_ptr<TLSKeyFile> keyPtr = std::make_shared<TLSKeyFile>();
    keyPtr->keyMaterial = keyMaterial;
    keyPtr->setFiletype("tlskey");
    return keyPtr;
}


void pcapfs::TLSKeyFile::serialize(boost::archive::text_oarchive &archive) {
    File::serialize(archive);
    archive << keyMaterial;
}


void pcapfs::TLSKeyFile::deserialize(boost::archive::text_iarchive &archive) {
    File::deserialize(archive);
    archive >> keyMaterial;
}


bool pcapfs::TLSKeyFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("tlskey", pcapfs::TLSKeyFile::create);
