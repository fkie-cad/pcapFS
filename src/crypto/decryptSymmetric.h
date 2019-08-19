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
#include "../crypto/plainTextElement.h"

namespace pcapfs {
    
    class Crypto {
        public:
            //deprecated
            static pcapfs::Bytes decryptRc4(uint64_t padding, size_t length, char *data, char *mac, char *key, char *iv);
            
            //will be deprecated
            
            /*
             * 
             * TODO: pass to each function only key, padding, hmac, iv, etc. Do the filtering if client and server as well as parsing the information before that step.
             * 
             */
            
            static pcapfs::Bytes decrypt_RC4_128(       uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_RC4_40(        uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_RC4_56(        uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_RC4_64(        uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            
            static pcapfs::Bytes decrypt_AES_128_CBC(   uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_AES_256_CBC(   uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_AES_128_GCM(   uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            static pcapfs::Bytes decrypt_AES_256_GCM(   uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv);
            
            //new stuff:
            static pcapfs::Bytes decrypt_RC4_128_NEW(uint64_t padding, size_t length, unsigned char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output);
            static pcapfs::Bytes decrypt_AES_128_CBC_NEW(uint64_t padding, size_t length, unsigned char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output);
    };

}

#endif //DECRYPT_SYMMETRIC_H
