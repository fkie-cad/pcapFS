#ifndef DECRYPT_SYMMETRIC_H
#define DECRYPT_SYMMETRIC_H

#include <openssl/evp.h>
#include <pcapplusplus/SSLLayer.h>
#include "ciphertextelement.h"

#include <memory>


namespace pcapfs {
    namespace crypto {

    		int getMacSize(const pcpp::SSLHashingAlgorithm &macAlg);

            void decrypt_RC4_128(const std::shared_ptr<CipherTextElement> &input,
                                Bytes &output,
                                const pcpp::SSLHashingAlgorithm &macAlg);

            void decrypt_AES_CBC(const std::shared_ptr<CipherTextElement> &input,
                                Bytes &output,
                                const pcpp::SSLHashingAlgorithm &macAlg,
                                const int key_len);

            void decrypt_AES_GCM(const std::shared_ptr<CipherTextElement> &input,
                                Bytes &output,
                                const int key_len);

            int opensslDecrypt(const EVP_CIPHER* cipher, const unsigned char* key,
                                const unsigned char* iv, const Bytes &dataToDecrypt, Bytes &decryptedData);
    }
}

#endif //DECRYPT_SYMMETRIC_H
