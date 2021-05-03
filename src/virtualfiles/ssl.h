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

        size_t getFullCipherText(uint64_t startOffset, size_t length, const Index &idx, std::vector< std::shared_ptr<CipherTextElement>> &outputCipherTextVector);
        size_t decryptCiphertextVecToPlaintextVec( std::vector< std::shared_ptr<CipherTextElement>> &cipherTextVector, std::vector< std::shared_ptr<PlainTextElement>> &outputPlainTextVector);
        
        int calculateProcessedSize(const Index &idx);

        static bool isClientMessage(uint64_t i);

        //ssl decrypt functions
        static Bytes createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom, uint16_t sslVersion);

        Bytes decryptData(uint64_t padding, size_t length, char* data, char* key_material, bool isClientMessage);
        //The new implementation of decryptData, we return nothing but change the values in the PlainTextElement *output parameter via call-by-reference.
        void decryptDataNew(uint64_t padding, size_t length, char *cipherText, char* key_material, bool isClientMessage, PlainTextElement* output);
            
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
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SSL_H
