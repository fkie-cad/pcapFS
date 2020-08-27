#include "decryptSymmetric.h"

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


pcapfs::Bytes pcapfs::Crypto::decrypt_RC4_128(uint64_t padding, size_t length, unsigned char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    /*
     * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
     * 
     * This is basically the key idea when using symmetric decryption in openssl
     * 
     * And this manpage contains additional information about the API:
     * https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     */

    /*
     * Padding is usually zero.
     */
    
    const int mac_size=16;
    const int key_size = 16;
    const int iv_size = 0;
    
    int return_code = 0;    
    int len = 0;
    int plaintext_len = 0;
    
    unsigned char plainText[length];
    memset(plainText, 0, length);
    
    printf("mac:\n");
    BIO_dump_fp (stdout, (const char *)mac, 16);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *)key, 16);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *)iv, 0);
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, length);
    
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
    }
    
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * EVP_CipherInit_ex(), EVP_CipherUpdate() and EVP_CipherFinal_ex() are functions that can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged
     * (the actual value of 'enc' being supplied in a previous call).
     * 
     */
    
    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    return_code = EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, NULL, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, plainText, &len, ciphertext, length);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , inl now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, plainText + len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , inl now: " << len << std::endl;
    }
    plaintext_len += len;
     
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char*) plainText, plaintext_len);    

    EVP_CIPHER_CTX_cleanup(ctx);
    
    for(int i=0; i<plaintext_len; i++) {
        output->plaintextBlock.push_back(plainText[i]);
    }
    
    return output->plaintextBlock;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_AES_128_CBC(uint64_t padding, size_t length, unsigned char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    LOG_DEBUG << "entering decrypt_AES_128_CBC - padding: " << std::to_string(padding) << " length: " << std::to_string(length)  << std::endl;
    
    printf("mac:\n");
    BIO_dump_fp (stdout, (const char *) mac, 20);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *) key, 16);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *) iv, 16);
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, dataToDecrypt.size());
    
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
    }
    
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * EVP_CipherInit_ex(), EVP_CipherUpdate() and EVP_CipherFinal_ex() are functions that can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged
     * (the actual value of 'enc' being supplied in a previous call).
     * 
     */
    
    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the padding
    //decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    
    //decryptedData.erase(decryptedData.begin()+ plaintext_len-padding - 20 - 1, decryptedData.end());
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    //BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding);
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    printf("\n\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding - 20 - 1);
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_AES_256_CBC(uint64_t padding, size_t length, unsigned char *ciphertext, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    LOG_DEBUG << "entering decrypt_AES_256_CBC - padding: " << std::to_string(padding) << " length: " << std::to_string(length)  << std::endl;
    
    printf("mac:\n");
    BIO_dump_fp (stdout, (const char *) mac, 20);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *) key, 32);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *) iv, 16);
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, dataToDecrypt.size());
    
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
    }
    
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * EVP_CipherInit_ex(), EVP_CipherUpdate() and EVP_CipherFinal_ex() are functions that can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged
     * (the actual value of 'enc' being supplied in a previous call).
     * 
     */
    
    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the padding
    //decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    
    //decryptedData.erase(decryptedData.begin()+ plaintext_len-padding - 20 - 1, decryptedData.end());
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    //BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding);
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    printf("\n\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding - 20 - 1);
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}


pcapfs::Bytes pcapfs::Crypto::decrypt_AES_256_GCM(uint64_t padding, size_t length,  unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *additional_data, PlainTextElement *output) {
    
    unsigned char public_nonce[12] = {0};
    memcpy(public_nonce, iv, 4);
    memcpy(public_nonce+4, ciphertext, 8);
    
    /*
     * Adjust ciphertext to reduce it by the nonce part.
     */
    
    
    
    unsigned char* auth_tag[16] = {0};
    memcpy(auth_tag, ciphertext+length-16, 16);
    
    ciphertext = ciphertext + 8;
    length = length - 8 - 16;
    
    printf("AAD:\n");
    BIO_dump_fp (stdout, (const char*) additional_data, 13);
    printf("auth_tag:\n");
    BIO_dump_fp (stdout, (const char*) auth_tag, 16);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *) key, 32);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *) iv, 4);
    printf("public nonce:\n");
    BIO_dump_fp (stdout, (const char*) public_nonce, 12);
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, padding + length);
    
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
    }
    
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * EVP_CipherInit_ex(), EVP_CipherUpdate() and EVP_CipherFinal_ex() are functions that can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged
     * (the actual value of 'enc' being supplied in a previous call).
     * 
     */
    
    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    //return_code = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv, 0);
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, public_nonce, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    /* Set IV length to 12 byte */
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    //return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, public_nonce);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    // Add AAD data:
    return_code = EVP_DecryptUpdate(ctx, NULL, &len, additional_data, 13);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. (AAD step) It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. (AUTH TAG) It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len);
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

//See https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
pcapfs::Bytes pcapfs::Crypto::decrypt_AES_128_GCM(uint64_t padding, size_t length,  unsigned char *ciphertext, unsigned char *key, unsigned char *iv, unsigned char *additional_data, PlainTextElement *output) {

    unsigned char public_nonce[12] = {0};
    memcpy(public_nonce, iv, 4);
    memcpy(public_nonce+4, ciphertext, 8);
    
    /*
     * Adjust ciphertext to reduce it by the nonce part.
     */
    
    
    
    unsigned char* auth_tag[16] = {0};
    memcpy(auth_tag, ciphertext+length-16, 16);
    
    ciphertext = ciphertext + 8;
    length = length - 8 - 16;
    
    printf("AAD:\n");
    BIO_dump_fp (stdout, (const char*) additional_data, 13);
    printf("auth_tag:\n");
    BIO_dump_fp (stdout, (const char*) auth_tag, 16);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *) key, 16);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *) iv, 4);
    printf("public nonce:\n");
    BIO_dump_fp (stdout, (const char*) public_nonce, 12);
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, padding + length);
    
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    
    if(ctx == NULL) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
    }
    
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * EVP_CipherInit_ex(), EVP_CipherUpdate() and EVP_CipherFinal_ex() are functions that can be used for decryption or encryption.
     * The operation performed depends on the value of the enc parameter.
     * It should be set to 1 for encryption, 0 for decryption and -1 to leave the value unchanged
     * (the actual value of 'enc' being supplied in a previous call).
     * 
     */
    
    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    //return_code = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv, 0);
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, public_nonce, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    /* Set IV length to 12 byte */
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    //return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, public_nonce);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }

    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    // Add AAD data:
    return_code = EVP_DecryptUpdate(ctx, NULL, &len, additional_data, 13);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. (AAD step) It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. (AUTH TAG) It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len);
    
        
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

































