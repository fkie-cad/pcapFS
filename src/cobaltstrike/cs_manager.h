#ifndef PCAPFS_CS_MANAGER_H
#define PCAPFS_CS_MANAGER_H

#include <set>
#include "../commontypes.h"
#include "../index.h"
#include "../virtualfiles/cobaltstrike.h"

namespace pcapfs {

    struct CobaltStrikeConnection {
        std::string serverIp;
        std::string serverPort;
        std::string clientIp;
        Bytes aesKey;

    };

    typedef std::shared_ptr<CobaltStrikeConnection> CobaltStrikeConnectionPtr;

    struct CsEmbeddedFileChunks {
        FilePtr firstFileChunk;
        std::vector<FilePtr> fileChunks;
    };

    typedef std::shared_ptr<CsEmbeddedFileChunks> CsEmbeddedFileChunksPtr;


    class CobaltStrikeManager {
    public:
        static CobaltStrikeManager& getInstance() {
            static CobaltStrikeManager instance;
            return instance;
        }

        CobaltStrikeManager(CobaltStrikeManager const&) = delete;
        void operator=(CobaltStrikeManager const&) = delete;

        void handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp, const Index &idx);
        CobaltStrikeConnectionPtr const getConnectionData(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);
        bool isKnownConnection(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);

        // functions managing fragmented file uploads
        void addFilePtrToUploadedFiles(const std::string &filename, const FilePtr& fileToAdd, bool isFirstChunk);
        std::vector<FilePtr> const getUploadedFileChunks(const FilePtr& uploadedFile);
        bool isFirstPartOfUploadedFile(const FilePtr &file);

    private:
        CobaltStrikeManager() {}

        bool matchMagicBytes(const Bytes& input);
        void addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp);

        std::vector<CobaltStrikeConnectionPtr> connections;

        CobaltStrikeFilePtr currUploadedFile;
        // key: filename, values: files where the upload happens
        std::map<std::string, CsEmbeddedFileChunksPtr> uploadedFiles;
    };
}

#endif // PCAPFS_CS_MANAGER_H
