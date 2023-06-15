#include "xor.h"

#include "../filefactory.h"
#include "../keyfiles/xorkey.h"
#include "../logging.h"
#include "../properties.h"


namespace {
    const char *FILE_TYPE_NAME = "xor";
}


std::vector<pcapfs::FilePtr> pcapfs::XorFile::parse(FilePtr filePtr, Index &idx) {
    std::vector<FilePtr> resultVector;
    //TODO: segfault if this is applied to metadata (why?)
    const std::shared_ptr<XORKeyFile> keyPtr = getCorrectXorKeyFile(filePtr, idx);
    if (keyPtr && !filePtr->flags.test(pcapfs::flags::IS_METADATA)) {
        std::shared_ptr<XorFile> resultPtr = std::make_shared<XorFile>();
        Fragment fragment{};
        fragment.start = 0;
        fragment.id = filePtr->getIdInIndex();
        fragment.length = filePtr->getFilesizeProcessed();
        resultPtr->fragments.push_back(fragment);
        resultPtr->setFilesizeRaw(filePtr->getFilesizeRaw());

        // Filesize processed is equal to file size raw when XORed.
        resultPtr->setFilesizeProcessed(filePtr->getFilesizeRaw());

        resultPtr->setOffsetType(filePtr->getFiletype());
        resultPtr->setTimestamp(filePtr->getTimestamp());
        resultPtr->filename = FILE_TYPE_NAME;
        resultPtr->setProperty(pcapfs::prop::srcIp, filePtr->getProperty(pcapfs::prop::srcIp));
        resultPtr->setProperty(pcapfs::prop::dstIp, filePtr->getProperty(pcapfs::prop::dstIp));
        resultPtr->setProperty(pcapfs::prop::srcPort, filePtr->getProperty(pcapfs::prop::srcPort));
        resultPtr->setProperty(pcapfs::prop::dstPort, filePtr->getProperty(pcapfs::prop::dstPort));
        resultPtr->setProperty(pcapfs::prop::proto, FILE_TYPE_NAME);
        resultPtr->setFiletype(FILE_TYPE_NAME);

        idx.insert(keyPtr);
        resultPtr->keyIdInIndex = keyPtr->getIdInIndex();
        resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);
        resultVector.push_back(resultPtr);

    }
    return resultVector;
}


size_t pcapfs::XorFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: right now this assumes each xor file only contains ONE offset into a tcp stream
    if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
        //TODO: how to without dynamic pointer cast?
        std::shared_ptr<XORKeyFile> keyPtr = std::dynamic_pointer_cast<XORKeyFile>(idx.get({"xorkey", keyIdInIndex}));
        Fragment fragment = fragments.at(0);
        FilePtr filePtr = idx.get({offsetType, fragment.id});
        Bytes rawData(fragment.length);
        filePtr->read(fragment.start, length, idx, (char *) rawData.data());
        Bytes key = keyPtr->getXORKey();
        XOR(rawData, (char *) key.data(), key.size());
        size_t read_count = std::min((size_t) fragment.length - startOffset, length);
        memcpy(buf, (char *) rawData.data() + startOffset, read_count);
        return read_count;
    }
    return 0;
}


const std::shared_ptr<pcapfs::XORKeyFile> pcapfs::XorFile::getCorrectXorKeyFile(const FilePtr &filePtr, const Index &idx){
    std::string keyFilename;
    for (const auto &map : config.getDecodeMapFor("xor")) {
        bool foundMatchingEntry = true;
        for (const auto &entry: map) {
            if (entry.first != "keyfile" && filePtr->getProperty(entry.first) != entry.second) {
                foundMatchingEntry = false;
                break;
            } else if (entry.first == "keyfile")
                keyFilename = entry.second;
        }

        if (foundMatchingEntry) {
            // at this point, the decode map criteria is met and we get the corresponding xor key
            if (!idx.getCandidatesOfType("xorkey").empty()) {
                if (keyFilename.empty()) {
                    // "keyfile" property in decode.xor.properties of the config is not set
                    // then, we take the first xor file we find
                    const std::vector<FilePtr> keyFiles = idx.getCandidatesOfType("xorkey");
                    return std::dynamic_pointer_cast<XORKeyFile>(keyFiles.at(0));
                } else {
                    // else: get key file with matching filename
                    const std::shared_ptr<XORKeyFile> keyPtr = getKeyFileFromName(idx, keyFilename);
                    if(keyPtr)
                        return keyPtr;
                    else {
                        LOG_WARNING << "XOR key file provided via decode.xor.properties not found.";
                        return nullptr;
                    }
                }
            } else {
                LOG_WARNING << "Found fitting XOR decode property but no key file provided.";
                return nullptr;
            }
        }

        keyFilename = "";
    }
    return nullptr;
}


const std::shared_ptr<pcapfs::XORKeyFile> pcapfs::XorFile::getKeyFileFromName(const Index &idx, const std::string &name) {
    const std::vector<FilePtr> keyFiles = idx.getCandidatesOfType("xorkey");
    auto it = std::find_if(keyFiles.begin(), keyFiles.end(), [name](const auto &keyFile){ return keyFile->getFilename() == name; });
    if (it != keyFiles.end())
        return std::dynamic_pointer_cast<XORKeyFile>(*it);
    else
        return nullptr;
}


void pcapfs::XorFile::XOR(Bytes &data, char *key, size_t keySize) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = data[i] ^ *(key + (i % keySize));
    }
}


auto registeredAtFactory = pcapfs::FileFactory::registerAtFactory(FILE_TYPE_NAME, pcapfs::XorFile::create,
                                                                  pcapfs::XorFile::parse);
