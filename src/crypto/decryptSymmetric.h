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
            
            
                        
            
            /*
             * 
             * TODO: pass to each function only key, padding, hmac, iv, etc. Do the filtering if client and server as well as parsing the information before that step.
             * 
             */
            
            
            //new stuff:
            static pcapfs::Bytes decrypt_RC4_128(       uint64_t padding, size_t length, char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, bool isClientMessage, PlainTextElement *output);
            static pcapfs::Bytes decrypt_AES_128_CBC(   uint64_t padding, size_t length, char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output);
            static pcapfs::Bytes decrypt_AES_256_CBC(   uint64_t padding, size_t length, char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output);

            
            // GCM needs "additional data", see section 6.2.3.3 RFC 5246 (hint-> the sequence number is built by +1 for each new TLS record (and NOT FOR EACH APPLICATION DATA PACKET!) and client and server keep their counters separately.)
            static pcapfs::Bytes decrypt_AES_128_GCM(   uint64_t padding, size_t length, char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *additional_data, PlainTextElement *output);
            static pcapfs::Bytes decrypt_AES_256_GCM(   uint64_t padding, size_t length, char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *additional_data, PlainTextElement *output);
            
    };

}

#endif //DECRYPT_SYMMETRIC_H