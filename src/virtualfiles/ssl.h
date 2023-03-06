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

    const std::set<uint16_t> supportedCipherSuiteIds = {
        0x0004, // TLS_RSA_WITH_RC4_128_MD5
        0x0005, // TLS_RSA_WITH_RC4_128_SHA
        0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
        0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x0034, // TLS_DH_anon_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x003A, // TLS_DH_anon_WITH_AES_256_CBC_SHA
        0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
        0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0x006C, // TLS_DH_anon_WITH_AES_128_CBC_SHA256
        0x006D, // TLS_DH_anon_WITH_AES_256_CBC_SHA256
        0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x00A6, // TLS_DH_anon_WITH_AES_128_GCM_SHA256
        0x00A7, // TLS_DH_anon_WITH_AES_256_GCM_SHA384
        0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
        0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xC016, // TLS_ECDH_anon_WITH_RC4_128_SHA
        0xC018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
        0xC019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
        0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        };

    struct TLSHandshakeData {
        TLSHandshakeData() : clientRandom(CLIENT_RANDOM_SIZE), serverRandom(SERVER_RANDOM_SIZE), rsaIdentifier(8),
                             handshakeMessagesRaw(0), sessionHash(0), encryptedPremasterSecret(0), certificates(0) {}
        bool processedTLSHandshake = false;
        bool clientChangeCipherSpec = false;
        bool serverChangeCipherSpec = false;
        bool encryptThenMac = false;
        bool truncatedHmac = false;
        bool extendedMasterSecret = false;
        uint64_t clientEncryptedData = 0;
		uint64_t serverEncryptedData = 0;
        uint16_t sslVersion = pcpp::SSLVersion::SSL2;
        unsigned int iteration = 0;

        Bytes clientRandom;
        Bytes serverRandom;
        Bytes rsaIdentifier;
        Bytes handshakeMessagesRaw;
        Bytes sessionHash;
        Bytes encryptedPremasterSecret;
        std::vector<FilePtr> certificates;
        pcpp::SSLCipherSuite* cipherSuite = pcpp::SSLCipherSuite::getCipherSuiteByID(0);
    };

    class SslFile : public VirtualFile {
    public:

        static FilePtr create() { return std::make_shared<SslFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;
        size_t readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readDecryptedContent(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readCertificate(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        std::string convertToPem(const Bytes &input);

        size_t getFullCipherText(const Index &idx, std::vector<std::shared_ptr<CipherTextElement>> &outputCipherTextVector);

        void decryptCiphertextVecToPlaintextVec(
            const std::vector<std::shared_ptr<CipherTextElement>> &cipherTextVector,
            std::vector<Bytes> &outputPlainTextVector);

        size_t calculateProcessedSize(const Index& idx);
        size_t calculateProcessedCertSize(const Index &idx);

        static void processTLSHandshake(pcpp::SSLLayer *sslLayer, std::shared_ptr<TLSHandshakeData> &handshakeData, uint64_t &offset,
                                        const FilePtr &fileptr, const Index &idx);

        static std::vector<FilePtr> createCertFiles(const FilePtr &filePtr, uint64_t offset, pcpp::SSLCertificateMessage* certificateMessage, const Index &idx);

        static Bytes const calculateSessionHash(const std::shared_ptr<TLSHandshakeData> &handshakeData);

        static void initResultPtr(const std::shared_ptr<SslFile> &resultPtr, const FilePtr &filePtr,
                            const std::shared_ptr<TLSHandshakeData> &handshakeData, Index &idx);

        static bool isClientMessage(uint64_t i);

    	static bool isTLSTraffic(const FilePtr &filePtr);

        static Bytes const createKeyMaterial(const Bytes &input, const std::shared_ptr<TLSHandshakeData> &handshakeData, bool deriveMasterSecret);

        static bool isSupportedCipherSuite(const pcpp::SSLCipherSuite* cipherSuite);

        int decryptData(const std::shared_ptr<CipherTextElement> &input, Bytes &output);

        static Bytes searchCorrectMasterSecret(const std::shared_ptr<TLSHandshakeData> &handshakeData, const Index &idx);

        static Bytes decryptPreMasterSecret(const Bytes &encryptedPremasterSecret, const Bytes &rsaPrivateKey);

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        std::string toString();

        uint64_t getKeyIDinIndex() { return keyIDinIndex; };

        std::string getCipherSuite() { return cipherSuite; };

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
