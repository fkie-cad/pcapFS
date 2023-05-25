#ifndef PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H
#define PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H

#include "virtualfile.h"

namespace pcapfs {

    struct CsEmbeddedFileInfo{
        uint64_t id;
        std::string command;
        std::string filename;
        size_t size;
        bool isChunk;
    };

    typedef std::shared_ptr<CsEmbeddedFileInfo> EmbeddedFileInfoPtr;

    class CobaltStrikeFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<CobaltStrikeFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        static bool isHttpPost(const std::string &filename);

        static bool isHttpResponse(const std::string &filename);

        size_t calculateProcessedSize(const Index &idx, std::string &command);

        std::string const extractServerCommand(const Bytes &payload);

        Bytes const decryptPayload(const Bytes &input);

        int opensslDecryptCS(const Bytes &dataToDecrypt, Bytes &decryptedData);

        Bytes const parseDecryptedClientContent(const std::vector<Bytes> &decryptedChunks);

        Bytes const parseDecryptedServerContent(const Bytes &data);

        size_t getLengthWithoutPadding(const Bytes &input, uint32_t inputLength);

        std::vector<EmbeddedFileInfoPtr> checkEmbeddedFiles(const Index &idx);

        Bytes const decryptEmbeddedFile(const Bytes &input);

        std::vector<EmbeddedFileInfoPtr> extractEmbeddedFileInfos(const Bytes &input);

        bool showFile() override;

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

    protected:
        static bool registeredAtFactory;

        Bytes cobaltStrikeKey;
        bool fromClient;
        uint64_t embeddedFileIndex;

    };

    typedef std::shared_ptr<CobaltStrikeFile> CobaltStrikeFilePtr;


    class CsUploadedFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<CsUploadedFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    protected:
        static bool registeredAtFactory;
    };

}
#endif //PCAPFS_VIRTUAL_FILES_COBALTSTRIKE_H
