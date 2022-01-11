#ifndef PCAPFS_VIRTUAL_FILES_SSL_H
#define PCAPFS_VIRTUAL_FILES_SSL_H

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/shared_ptr.hpp>
#include <pcapplusplus/SSLLayer.h>

#include "../file.h"
#include "../keyfiles/sslkey.h"
#include "virtualfile.h"
#include "../crypto/cipherTextElement.h"
#include "../crypto/plainTextElement.h"
#include "../crypto/decryptSymmetric.h"



namespace pcapfs {

    class SslFile : public VirtualFile {
    public:

    	SslFile();

        static FilePtr create() { return std::make_shared<SslFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;
        size_t read_for_size(uint64_t startOffset, size_t length, const Index &idx);

        size_t getFullCipherText(uint64_t startOffset, size_t length, const Index &idx, std::vector< std::shared_ptr<CipherTextElement>> &outputCipherTextVector);
        size_t decryptCiphertextVecToPlaintextVec( std::vector< std::shared_ptr<CipherTextElement>> &cipherTextVector, std::vector< std::shared_ptr<PlainTextElement>> &outputPlainTextVector);
        
        int calculateProcessedSize(uint64_t filesizeRaw, Index &idx);

        static bool isClientMessage(uint64_t i);

    	static bool isTLSTraffic(const FilePtr &filePtr, bool isTLSTraffic);

        //ssl decrypt functions
        static Bytes createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom, uint16_t sslVersion);

        //Bytes decryptData(uint64_t virtual_file_offset, size_t length, char* data, char* key_material, bool isClientMessage);
        //The new implementation of decryptData, we return nothing but change the values in the PlainTextElement *output parameter via call-by-reference.
        void decryptDataNew(uint64_t virtual_file_offset, size_t length, char *cipherText, char* key_material, bool isClientMessage, PlainTextElement* output);
            
        static Bytes searchCorrectMasterSecret(char *clientRandom, const Index &idx);

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        std::string toString();

    private:
        std::string cipherSuite;
        uint16_t sslVersion;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;

	static bool processTLSHandshake(bool processedSSLHandshake, unsigned int i,
			bool clientChangeCipherSpec, bool serverChangeCipherSpec,
			pcpp::SSLHandshakeLayer *handshakeLayer, Bytes &clientRandom,
			uint64_t &offsetInLogicalFragment, Bytes &serverRandom,
			std::string &cipherSuite, pcpp::SSLVersion &sslVersion,
			pcpp::SSLLayer *sslLayer, uint64_t &clientEncryptedData,
			uint64_t &serverEncryptedData);

	static void resultPtrInit(bool processedSSLHandshake,
			pcpp::SSLVersion sslVersion,
			const std::shared_ptr<SslFile> &resultPtr, const FilePtr &filePtr,
			const std::string &cipherSuite, unsigned int i, Bytes &clientRandom,
			Index &idx, Bytes &serverRandom);
};
}

#endif //PCAPFS_VIRTUAL_FILES_SSL_H
