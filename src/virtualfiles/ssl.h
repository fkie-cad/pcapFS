#ifndef PCAPFS_VIRTUAL_FILES_SSL_H
#define PCAPFS_VIRTUAL_FILES_SSL_H

#include <iostream>
#include <string>
#include <vector>
#include <set>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <pcapplusplus/SSLLayer.h>

#include "../file.h"
#include "../keyfiles/sslkey.h"
#include "virtualfile.h"
#include "../crypto/cipherTextElement.h"

namespace pcapfs {

    size_t const CLIENT_RANDOM_SIZE = 32;
    size_t const SERVER_RANDOM_SIZE = 32;

    struct TLSHandshakeData {
        TLSHandshakeData() : clientRandom(CLIENT_RANDOM_SIZE), serverRandom(SERVER_RANDOM_SIZE), rsaIdentifier(8),
                             handshakeMessagesRaw(0), sessionHash(0), encryptedPremasterSecret(0), certificates(0),
                             serverCertificate(0) {}
        bool processedTLSHandshake = false;
        bool clientChangeCipherSpec = false;
        bool serverChangeCipherSpec = false;
        bool encryptThenMac = false;
        bool truncatedHmac = false;
        bool extendedMasterSecret = false;
        uint64_t clientEncryptedData = 0;
		uint64_t serverEncryptedData = 0;
        uint16_t sslVersion = 0;
        unsigned int iteration = 0;

        Bytes clientRandom;
        Bytes serverRandom;
        Bytes rsaIdentifier;
        Bytes handshakeMessagesRaw;
        Bytes sessionHash;
        Bytes encryptedPremasterSecret;
        std::vector<FilePtr> certificates;
        Bytes serverCertificate;
        pcpp::SSLCipherSuite* cipherSuite = nullptr;
    };

    class SslFile : public VirtualFile {
    public:

        static FilePtr create() { return std::make_shared<SslFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;
        size_t readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readDecryptedContent(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readCertificate(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        std::string const convertToPem(const Bytes &input);

        size_t getFullCipherText(const Index &idx, std::vector<std::shared_ptr<CipherTextElement>> &outputCipherTextVector);

        void decryptCiphertextVecToPlaintextVec(
            const std::vector<std::shared_ptr<CipherTextElement>> &cipherTextVector,
            std::vector<Bytes> &outputPlainTextVector);

        size_t calculateProcessedSize(const Index& idx);
        size_t calculateProcessedCertSize(const Index &idx);

        static void processTLSHandshake(pcpp::SSLLayer *sslLayer, std::shared_ptr<TLSHandshakeData> &handshakeData, uint64_t &offset,
                                        const FilePtr &fileptr, const Index &idx);

        static void createCertFiles(const FilePtr &filePtr, uint64_t offset, pcpp::SSLCertificateMessage* certificateMessage,
                                                        const std::shared_ptr<TLSHandshakeData> &handshakeData, const Index &idx);

        static Bytes const calculateSessionHash(const std::shared_ptr<TLSHandshakeData> &handshakeData);

        static void initResultPtr(const std::shared_ptr<SslFile> &resultPtr, const FilePtr &filePtr,
                            const std::shared_ptr<TLSHandshakeData> &handshakeData, Index &idx);

        static bool isClientMessage(uint64_t i);

    	static bool isTLSTraffic(const FilePtr &filePtr);

        static Bytes const createKeyMaterial(const Bytes &input, const std::shared_ptr<TLSHandshakeData> &handshakeData, bool deriveMasterSecret);

        static bool isSupportedCipherSuite(const pcpp::SSLCipherSuite* cipherSuite);

        int decryptData(const std::shared_ptr<CipherTextElement> &input, Bytes &output);

        static Bytes const searchCorrectMasterSecret(const std::shared_ptr<TLSHandshakeData> &handshakeData, const Index &idx);

        static Bytes const decryptPreMasterSecret(const Bytes &encryptedPremasterSecret, const Bytes &rsaPrivateKey);

        static int matchPrivateKey(const Bytes &rsaPrivateKey, const Bytes &serverCertificate);

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        std::string const toString();

        uint64_t getKeyIDinIndex() { return keyIDinIndex; };

        std::string const getCipherSuite() { return cipherSuite; };

        uint16_t getSslVersion() { return sslVersion; };

        void setKeyIDinIndex(uint64_t keyIDinIndex) { this->keyIDinIndex = keyIDinIndex; };

        void setCipherSuite(const std::string &cipherSuite) { this->cipherSuite = cipherSuite; };

        void setSslVersion(uint16_t sslVersion) { this->sslVersion = sslVersion; };

        bool encryptThenMacEnabled;
        bool truncatedHmacEnabled;

    protected:
        std::string cipherSuite;
        uint16_t sslVersion;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SSL_H
