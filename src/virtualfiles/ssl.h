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
#include "../crypto/plainTextElement.h"

namespace pcapfs {

    size_t const CLIENT_RANDOM_SIZE = 32;
    size_t const SERVER_RANDOM_SIZE = 32;

    const std::set<uint16_t> supportedCipherSuiteIds = {
        0x04, 0x05, 0x2F, 0x35, 0x3C, 0x3D, 0x9C, 0x9D }; 
    
    struct TLSHandshakeData {
        TLSHandshakeData() : clientRandom(CLIENT_RANDOM_SIZE), serverRandom(SERVER_RANDOM_SIZE) {}
        bool processedTLSHandshake = false;
        bool clientChangeCipherSpec = false;
        bool serverChangeCipherSpec = false;
        bool encryptThenMac = false;
        uint64_t clientEncryptedData = 0;
		uint64_t serverEncryptedData = 0;
        uint16_t sslVersion = pcpp::SSLVersion::SSL2;
        unsigned int iteration = 0;

        Bytes clientRandom;
        Bytes serverRandom;
        std::string cipherSuite = ""; 
    };

    class SslFile : public VirtualFile {
    public:

        static FilePtr create() { return std::make_shared<SslFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;
        size_t read_for_plaintext_size(const Index &idx);
        size_t read_raw(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t read_decrypted_content(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        size_t getFullCipherText(const Index &idx, std::vector< std::shared_ptr<CipherTextElement>> &outputCipherTextVector);
        
        void decryptCiphertextVecToPlaintextVec(
            std::vector< std::shared_ptr<CipherTextElement>> &cipherTextVector,
            std::vector< std::shared_ptr<PlainTextElement>> &outputPlainTextVector);
        
        size_t calculateProcessedSize(const Index& idx);

        static void processTLSHandshake(pcpp::SSLLayer *sslLayer, std::shared_ptr<TLSHandshakeData> &handshakeData, uint64_t &offsetInLogicalFragment);

        static void initResultPtr(const std::shared_ptr<SslFile> &resultPtr, const FilePtr &filePtr,
                            const std::shared_ptr<TLSHandshakeData> &handshakeData, Index &idx);   

        static bool isClientMessage(uint64_t i);

    	static bool isTLSTraffic(const FilePtr &filePtr);

        static Bytes const createKeyMaterial(const Bytes &masterSecret, const std::shared_ptr<TLSHandshakeData> &handshakeData);
        
        static bool isSupportedCipherSuite(const std::string &cipherSuite);

        int decryptData(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output);

        static Bytes searchCorrectMasterSecret(const Bytes &clientRandom, const Index &idx);

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

    private:
        std::string cipherSuite;
        uint16_t sslVersion;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;    
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SSL_H
