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

    		int getMacSize(const pcpp::SSLHashingAlgorithm macAlg);

            
            //new stuff:
            void decrypt_RC4_128(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                pcpp::SSLHashingAlgorithm macAlg);

            void decrypt_AES_128_CBC(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                pcpp::SSLHashingAlgorithm macAlg);

            void decrypt_AES_256_CBC(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                pcpp::SSLHashingAlgorithm macAlg);

            
            // GCM needs "additional data", see section 6.2.3.3 RFC 5246 (hint-> the sequence number is built by +1 for each new TLS record (and NOT FOR EACH APPLICATION DATA PACKET!) and client and server keep their counters separately.)
            void decrypt_AES_128_GCM(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output);

            void decrypt_AES_256_GCM(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output);

            void opensslDecrypt(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, Bytes& dataToDecrypt, Bytes& decryptedData);
            
    }

}

#endif //DECRYPT_SYMMETRIC_H
