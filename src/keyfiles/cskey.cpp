#include "cskey.h"
#include "../filefactory.h"
#include <fstream>


namespace {
    const char *RSA_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
}

std::vector<pcapfs::FilePtr> pcapfs::CSKeyFile::parseCandidates(const std::vector<boost::filesystem::path> &keyFiles) {
    std::vector<pcapfs::FilePtr> resultVector;
    for (auto &keyFile: keyFiles) {
        std::ifstream infile(keyFile.string());
        std::string line;
        while (std::getline(infile, line)) {
            std::shared_ptr<CSKeyFile> keyPtr = std::make_shared<CSKeyFile>();

            if (line.rfind(RSA_KEY_BEGIN) != std::string::npos) {
                char elem;
                for(size_t i = 0; i < strlen(RSA_KEY_BEGIN); ++i)
                    keyPtr->rsaPrivateKey.push_back(RSA_KEY_BEGIN[i]);
                keyPtr->rsaPrivateKey.push_back(0x0a); // add newline

                while(infile.get(elem)) {
                    keyPtr->rsaPrivateKey.push_back(elem);
                }
                keyPtr->setFiletype("cskey");
                resultVector.push_back(keyPtr);

            } 
        }
    }
    return resultVector;
}


void pcapfs::CSKeyFile::serialize(boost::archive::text_oarchive &archive) {
    File::serialize(archive);
    archive << rsaPrivateKey;
}


void pcapfs::CSKeyFile::deserialize(boost::archive::text_iarchive &archive) {
    File::deserialize(archive);
    archive >> rsaPrivateKey;
}


bool pcapfs::CSKeyFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("cskey", pcapfs::CSKeyFile::create);