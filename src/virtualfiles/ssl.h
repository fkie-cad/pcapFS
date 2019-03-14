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
#include <pcapplusplus/SSLLayer.h>

#include "../file.h"
#include "../keyfiles/sslkey.h"
#include "virtualfile.h"


namespace pcapfs {

    class SslFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SslFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        int calculateProcessedSize(const Index &idx);

        static bool isClientMessage(uint64_t i);

        //ssl decrypt functions
        static Bytes createKeyMaterial(char *masterSecret, char *clientRandom, char *serverRandom);

        Bytes decryptData(uint64_t padding, size_t length, char* data, char* key, char* key_material);

        static Bytes decryptRc4(uint64_t padding, size_t length, char *data, char *key);

        static Bytes decrypt_RC4_128(uint64_t padding, size_t length, char *data, char *key);
        static Bytes decrypt_RC4_40(uint64_t padding, size_t length, char *data, char *key);
        static Bytes decrypt_RC4_56(uint64_t padding, size_t length, char *data, char *key);
        static Bytes decrypt_RC4_64(uint64_t padding, size_t length, char *data, char *key);
        static Bytes decrypt_AES_128_CBC(uint64_t padding, size_t length, char *data, char *key);
        
        static Bytes searchCorrectMasterSecret(char *clientRandom, const Index &idx);

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

    private:
        std::string cipherSuite;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SSL_H
