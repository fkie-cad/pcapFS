#ifndef DECRYPT_SYMMETRIC_H
#define DECRYPT_SYMMETRIC_H

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <pcapplusplus/SSLLayer.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rc4.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>

#include "../commontypes.h"
#include "../virtualfiles/ssl.h"
#include "../filefactory.h"
#include "../logging.h"


namespace pcapfs {
    
    class Crypto {
        public:
            
            static pcapfs::Bytes decryptRc4(uint64_t padding, size_t length, char *data, char *key);
            
            static pcapfs::Bytes decrypt_RC4_128(uint64_t padding, size_t length, char *data, char *key);
            static pcapfs::Bytes decrypt_RC4_40(uint64_t padding, size_t length, char *data, char *key);
            static pcapfs::Bytes decrypt_RC4_56(uint64_t padding, size_t length, char *data, char *key);
            static pcapfs::Bytes decrypt_RC4_64(uint64_t padding, size_t length, char *data, char *key);
            static pcapfs::Bytes decrypt_AES_128_CBC(uint64_t padding, size_t length, char *data, char *key, char *key_material);
        
    };

}

#endif //DECRYPT_SYMMETRIC_H
