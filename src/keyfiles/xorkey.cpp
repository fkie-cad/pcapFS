#include "xorkey.h"

#include <cctype>
#include <fstream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include "../filefactory.h"
#include "../logging.h"
#include "../utils.h"


namespace {
    const char *XOR_KEY_STRING = "XOR_KEY";
}

std::vector<pcapfs::FilePtr> pcapfs::XORKeyFile::parseCandidates(const Paths &keyFiles) {
    std::vector<pcapfs::FilePtr> resultVector;
    //TODO: support multiple key files
    for (auto &keyFile: keyFiles) {
        std::ifstream infile(keyFile.string());
        std::string line;
        while (std::getline(infile, line)) {
            std::shared_ptr<XORKeyFile> keyPtr = std::make_shared<XORKeyFile>();
            std::vector<std::string> splitInput;
            boost::split(splitInput, line, boost::is_any_of(" "));
            //TODO: check this before?
            if (splitInput.empty()) {
                LOG_ERROR << "Empty key file!";
                continue;
            }
            if (splitInput.at(0) == XOR_KEY_STRING) {
                keyPtr->XORKey = utils::hexStringToBytes(splitInput.at(1));
                keyPtr->setFiletype("xorkey");
                keyPtr->setFilename(keyFile.filename().string());
            }
            resultVector.push_back(keyPtr);
        }
    }
    return resultVector;
}


std::shared_ptr<pcapfs::XORKeyFile> pcapfs::XORKeyFile::createKeyFile(const Bytes &key) {
    std::shared_ptr<XORKeyFile> keyPtr = std::make_shared<XORKeyFile>();
    keyPtr->XORKey = key;
    keyPtr->setFiletype("xorkey");
    return keyPtr;
}




void pcapfs::XORKeyFile::serialize(boost::archive::text_oarchive &archive) {
    File::serialize(archive);
    archive << XORKey;
}


void pcapfs::XORKeyFile::deserialize(boost::archive::text_iarchive &archive) {
    File::deserialize(archive);
    archive >> XORKey;
}


bool pcapfs::XORKeyFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("xorkey", pcapfs::XORKeyFile::create);
