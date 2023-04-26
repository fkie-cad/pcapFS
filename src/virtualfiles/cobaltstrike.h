#ifndef PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H
#define PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H

#include "virtualfile.h"

namespace pcapfs {
    class CobaltStrikeFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<CobaltStrikeFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        static bool isHttpPost(const std::string &filename);

        //static bool isHttpResponse(const std::string &filename, const std::string &uri);

        int calculateProcessedSize(const Index &idx);

        Bytes const decryptPayload(const Bytes &input);

        int opensslDecryptCS(const Bytes &dataToDecrypt, Bytes &decryptedData);

        Bytes const parseDecryptedClientContent(const Bytes &data);

        Bytes const parseDecryptedServerContent(const Bytes &data);

        size_t getLengthWithoutPadding(const Bytes &input, uint32_t inputLength);

        std::map<uint64_t,std::string> checkEmbeddedFiles(const Index &idx);

        Bytes const decryptEmbeddedFile(const Bytes &input);

        std::map<uint64_t,std::string> extractEmbeddedFileInfos(const Bytes &input);

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

    protected:
        static bool registeredAtFactory;

        Bytes cobaltStrikeKey;
        bool fromClient;
        uint64_t embeddedFileIndex;

    };

}
#endif //PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H