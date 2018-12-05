#include "xor.h"

#include "../filefactory.h"
#include "../keyfiles/xorkey.h"
#include "../logging.h"


std::vector<pcapfs::FilePtr> pcapfs::XorFile::parse(FilePtr filePtr, Index &idx) {
    std::vector<FilePtr> resultVector;
    bool condition = filePtr->meetsDecodeMapCriteria("xor");
    //TODO: segfault if this is appliead to metadata (why?)
    if (condition & !filePtr->flags.test(pcapfs::flags::IS_METADATA)) {
        std::shared_ptr<XorFile> resultPtr = std::make_shared<XorFile>();
        SimpleOffset offset;
        offset.start = 0;
        offset.id = filePtr->getIdInIndex();
        offset.length = filePtr->getFilesizeProcessed();
        resultPtr->offsets.push_back(offset);
        resultPtr->setFilesizeRaw(filePtr->getFilesizeRaw());
        resultPtr->setOffsetType(filePtr->getFiletype());
        resultPtr->setTimestamp(filePtr->getTimestamp());
        resultPtr->filename = "xor";
        resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
        resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
        resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
        resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
        resultPtr->setProperty("protocol", "xor");
        resultPtr->setFiletype("xor");

        if (!idx.getCandidatesOfType("xorkey").empty()) {
            std::vector<FilePtr> keyFiles = idx.getCandidatesOfType("xorkey");
            //TODO: only one xor key possible!
            std::shared_ptr<XORKeyFile> keyPtr = std::dynamic_pointer_cast<XORKeyFile>(keyFiles.at(0));
            idx.insert(keyPtr);
            resultPtr->keyIdInIndex = keyPtr->getIdInIndex();
            resultPtr->flags.set(pcapfs::flags::HAS_DECRYPTION_KEY);
            resultVector.push_back(resultPtr);
        }
    }
    return resultVector;
}


size_t pcapfs::XorFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: right now this assumes each xor file only contains ONE offset into a tcp stream
    if (flags.test(pcapfs::flags::HAS_DECRYPTION_KEY)) {
        //TODO: how to without dynamic pointer cast?
        std::shared_ptr<XORKeyFile> keyPtr = std::dynamic_pointer_cast<XORKeyFile>(idx.get({"xorkey", keyIdInIndex}));
        SimpleOffset offset = offsets.at(0);
        FilePtr filePtr = idx.get({offsetType, offset.id});
        Bytes rawData(offset.length);
        filePtr->read(offset.start, length, idx, (char *) rawData.data());
        Bytes key = keyPtr->getXORKey();
        XOR(rawData, (char *) key.data(), key.size());
        size_t read_count = std::min((size_t) offset.length - startOffset, length);
        memcpy(buf, (char *) rawData.data() + startOffset, read_count);
        return read_count;
    }
    return 0;
}


void pcapfs::XorFile::XOR(Bytes &data, char *key, size_t keySize) {
    //xor can be done inplace
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = data[i] ^ *(key + (i % keySize));
    }
}


bool pcapfs::XorFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("xor", pcapfs::XorFile::create, pcapfs::XorFile::parse);