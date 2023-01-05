#ifndef DECRYPT_SYMMETRIC_H
#define DECRYPT_SYMMETRIC_H

#include <openssl/evp.h>
#include <pcapplusplus/SSLLayer.h>
#include "cipherTextElement.h"
#include "plainTextElement.h"

namespace pcapfs {

    namespace Crypto {
            
    		int getMacSize(const pcpp::SSLHashingAlgorithm macAlg);

            void decrypt_RC4_128(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                pcpp::SSLHashingAlgorithm macAlg);

            void decrypt_AES_CBC(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                pcpp::SSLHashingAlgorithm macAlg,
                                const int key_len);
            
            void decrypt_AES_GCM(std::shared_ptr<CipherTextElement> input,
                                std::shared_ptr<PlainTextElement> output,
                                const int key_len);

            int opensslDecrypt(const EVP_CIPHER* cipher, const unsigned char* key,
                                const unsigned char* iv, Bytes& dataToDecrypt, Bytes& decryptedData);
            
    }

}

#endif //DECRYPT_SYMMETRIC_H
