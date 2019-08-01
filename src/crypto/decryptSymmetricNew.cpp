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


//TODO:
pcapfs::Bytes pcapfs::Crypto::decrypt_AES_128_GCM(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
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
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    
    /* Set IV length to 4 byte */
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 4, NULL);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    
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
        
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding);
    
    
    LOG_DEBUG << "DECRYPTED AES DATA: " << decryptedContent << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

//TODO:
pcapfs::Bytes pcapfs::Crypto::decrypt_AES_256_GCM(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    
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
    
    char *iv_before_plain[16];
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    memcpy(iv_before_plain, decryptedContent.data()+padding+plaintext_len+20, 16);
    
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding);
    
    printf("cbc padding:\n");
    BIO_dump_fp (stdout, (const char *)iv_before_plain, 16);
    
    LOG_DEBUG << "DECRYPTED AES DATA: " << decryptedContent << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}








pcapfs::Bytes pcapfs::Crypto::decrypt_AES_128_CBC(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {

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
    
    //Bytes decryptedData(length-padding);
    //Bytes dataToDecrypt(length-padding);
    
    
    
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    //dataToDecrypt.insert(dataToDecrypt.end(), data + padding, data + length - padding);
    
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    //BIO_dump_fp (stdout, (const char *) dataToDecryptPtr + padding, length - padding);
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

pcapfs::Bytes pcapfs::Crypto::decrypt_AES_256_CBC(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
        
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
        
    
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
    
    char *iv_before_plain[16];
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    memcpy(iv_before_plain, decryptedContent.data()+padding+plaintext_len+20, 16);
    
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding+16, plaintext_len-padding);
    
    printf("cbc padding:\n");
    BIO_dump_fp (stdout, (const char *)iv_before_plain, 16);
    
    LOG_DEBUG << "DECRYPTED AES DATA: " << decryptedContent << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_RC4_128(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    /*
     * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
     * 
     * This is basically the key idea when using symmetric decryption in openssl
     * 
     * And this manpage contains additional information about the API:
     * https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     */
    
    int return_code;
    
    int len;
    int plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding: " << std::to_string(padding) << " and cipher text length: " << dataToDecrypt.size();
    
    //decrypt data using keys and RC4
    unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char *rc4_key = reinterpret_cast<unsigned char *>(key);
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)dataToDecrypt.data(), dataToDecrypt.size());
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL);
    
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
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    
    LOG_DEBUG << "DECRYPTED RC4 DATA: " << decryptedContent << " KEY TO USE: " << rc4_key << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_RC4_40(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    /*
     * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
     * 
     * This is basically the key idea when using symmetric decryption in openssl
     * 
     * And this manpage contains additional information about the API (for RC4_40):
     * https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     */
    
    const int KEY_SIZE_RC4_40 = 5;
    int return_code;
    
    int len;
    int plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding: " << std::to_string(padding) << " and cipher text length: " << dataToDecrypt.size();
    
    //decrypt data using keys and RC4
    unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char *rc4_key = reinterpret_cast<unsigned char *>(key);
    
    /*
     *    for(int i=0; i<16;i++) {
     *        if(i>= 16) {
     *            rc4_key[i] = '\0';
}
}
*/
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)dataToDecrypt.data(), dataToDecrypt.size());
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
    return_code = EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE_RC4_40);
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_set_key_length() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "KEY SIZE after update: " << EVP_CIPHER_CTX_key_length(ctx) << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL);
    
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
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len; 
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    
    LOG_DEBUG << "DECRYPTED RC4_40 DATA: " << decryptedContent << " KEY TO USE: " << rc4_key << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_RC4_56(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    /*
     * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
     * 
     * This is basically the key idea when using symmetric decryption in openssl
     * 
     * And this manpage contains additional information about the API (for RC4_40):
     * https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * It should work also with RC4_56, but this cipher is currently untestet since openssl does not support this traffic
     * 
     */
    
    const int KEY_SIZE_RC4_56 = 7;
    int return_code;
    
    int len;
    int plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding: " << std::to_string(padding) << " and cipher text length: " << dataToDecrypt.size();
    
    //decrypt data using keys and RC4
    unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char *rc4_key = reinterpret_cast<unsigned char *>(key);
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)dataToDecrypt.data(), dataToDecrypt.size());
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
    return_code = EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE_RC4_56);
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_set_key_length() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "KEY SIZE after update: " << EVP_CIPHER_CTX_key_length(ctx) << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL);
    
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
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len; 
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    
    LOG_DEBUG << "DECRYPTED RC4_56 DATA: " << decryptedContent << " KEY TO USE: " << rc4_key << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decrypt_RC4_64(uint64_t padding, size_t length, char *data, unsigned char *mac, unsigned char *key, unsigned char *iv, PlainTextElement *output) {
    
    /*
     * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
     * 
     * This is basically the key idea when using symmetric decryption in openssl
     * 
     * And this manpage contains additional information about the API (for RC4_40):
     * https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     * 
     * It should work also with RC4_64, but this cipher is currently untestet since openssl does not support this traffic
     * 
     */
    
    const int KEY_SIZE_RC4_64 = 8;
    int return_code;
    
    int len;
    int plaintext_len;
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding: " << std::to_string(padding) << " and cipher text length: " << dataToDecrypt.size();
    
    //decrypt data using keys and RC4
    unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char *rc4_key = reinterpret_cast<unsigned char *>(key);
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)dataToDecrypt.data(), dataToDecrypt.size());
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
    return_code = EVP_CIPHER_CTX_set_key_length(ctx, KEY_SIZE_RC4_64);
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_set_key_length() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "KEY SIZE after update: " << EVP_CIPHER_CTX_key_length(ctx) << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL);
    
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
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
        LOG_DEBUG << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + padding, plaintext_len-padding);
    
    LOG_DEBUG << "DECRYPTED RC4_64 DATA: " << decryptedContent << " KEY TO USE: " << rc4_key << std::endl;
    
    EVP_CIPHER_CTX_cleanup(ctx);
    
    return decryptedData;
}

pcapfs::Bytes pcapfs::Crypto::decryptRc4(uint64_t padding, size_t length, char *data, char *mac, char *key, char *iv) {
    
    Bytes decryptedData(padding + length);
    Bytes dataToDecrypt(padding);
    dataToDecrypt.insert(dataToDecrypt.end(), data, data + length);
    LOG_DEBUG << "decrypting with padding " << std::to_string(padding) << " of length " << dataToDecrypt.size();
    
    //decrypt data using keys and RC4
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    const unsigned char *keyToUse = reinterpret_cast<unsigned char *>(key);
    const int KEY_SIZE = 16;
    
    RC4_KEY rc4Key;
    RC4_set_key(&rc4Key, KEY_SIZE, keyToUse);
    RC4(&rc4Key, dataToDecrypt.size(), dataToDecryptPtr, decryptedData.data());
    
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding);
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    LOG_DEBUG << "DECRYPTED RC4 DATA: " << decryptedContent << " KEY TO USE: " << keyToUse << " KEY: " << key << std::endl;
        
    return decryptedData;
}
