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

    struct CsContentInfo{
        size_t filesize;
        std::string command;
        std::vector<EmbeddedFileInfoPtr> embeddedFileInfos;
    };
    typedef std::shared_ptr<CsContentInfo> CsContentInfoPtr;

    class CobaltStrikeFile;
    typedef std::shared_ptr<CobaltStrikeFile> CobaltStrikeFilePtr;


    class CobaltStrikeFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<CobaltStrikeFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        bool showFile() override;
        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

    private:
        static bool meetsParsingRequirements(const FilePtr &filePtr);

        static bool isHttpPost(const std::string &filename);
        static bool isHttpResponse(const std::string &filename);

        std::vector<Bytes>  const decryptClientPayload(const Bytes &input);
        Bytes const decryptServerPayload(const Bytes &input);

        CsContentInfoPtr const extractServerContent(const Bytes &input);
        CsContentInfoPtr const extractClientContent(const Bytes &input);

        std::string const handleKeystrokes(const std::string& input);

        static void fillEmbeddedFileProperties(CobaltStrikeFilePtr &embeddedFilePtr, const FilePtr &filePtr,
                                                const EmbeddedFileInfoPtr &embeddedFileInfo);

        Bytes const readClientContent(const Bytes &input);
        Bytes const readServerContent(const Bytes &input);
        Bytes const readEmbeddedServerFile(const Bytes &input);
        Bytes const readEmbeddedClientFile(const Bytes &input);

        int opensslDecryptCS(const Bytes &dataToDecrypt, Bytes &decryptedData, const Bytes &aesKey);
        std::string const extractServerCommand(const std::string &input);
        size_t getLengthWithoutPadding(const Bytes &input, uint32_t inputLength);
        size_t getEndOfJpgFile(const Bytes &input);

    protected:
        std::vector<Bytes> cobaltStrikeKeys;
        bool fromClient;
        uint64_t embeddedFileIndex;

        static bool registeredAtFactory;
    };



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
