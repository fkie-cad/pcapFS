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
#include "plainTextElement.h"

namespace pcapfs {

    namespace Crypto {
            
            /*
             * 
             * TODO: pass to each function only key, padding, hmac, iv, etc. Do the filtering if client and server as well as parsing the information before that step.
             * 
             */
            
            
            //new stuff:
            void decrypt_RC4_128(
            		uint64_t virtual_file_offset,
					size_t length,
					char *ciphertext,
					unsigned char *mac,
					unsigned char *key,
					bool isClientMessage,
					PlainTextElement *output);

            void decrypt_AES_128_CBC(
            		uint64_t virtual_file_offset,
					size_t length,
					char *ciphertext,
					unsigned char *mac,
					unsigned char *key,
					unsigned char *iv,
					bool isClientMessage,
					PlainTextElement *output);

            void decrypt_AES_256_CBC(
            		uint64_t virtual_file_offset,
					size_t length,
					char *ciphertext,
					unsigned char *mac,
					unsigned char *key,
					unsigned char *iv,
					bool isClientMessage,
					PlainTextElement *output);

            
            // GCM needs "additional data", see section 6.2.3.3 RFC 5246 (hint-> the sequence number is built by +1 for each new TLS record (and NOT FOR EACH APPLICATION DATA PACKET!) and client and server keep their counters separately.)
            void decrypt_AES_128_GCM(
            		uint64_t virtual_file_offset,
					size_t length,
					char *ciphertext,
					unsigned char *mac,
					unsigned char *key,
					unsigned char *iv,
					unsigned char *additional_data,
					bool isClientMessage,
					PlainTextElement *output);

            void decrypt_AES_256_GCM(
            		uint64_t virtual_file_offset,
					size_t length,
					char *ciphertext,
					unsigned char *mac,
					unsigned char *key,
					unsigned char *iv,
					unsigned char *additional_data,
					bool isClientMessage,
					PlainTextElement *output);
            
    }

}

#endif //DECRYPT_SYMMETRIC_H
