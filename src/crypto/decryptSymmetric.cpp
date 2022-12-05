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

using namespace pcapfs;

int pcapfs::Crypto::getMacSize(const pcpp::SSLHashingAlgorithm macAlg) {

	/*
	 * From https://tools.ietf.org/html/rfc5246#appendix-A.5
	 *
	 * 	MAC       Algorithm    mac_length  mac_key_length
		--------  -----------  ----------  --------------
		NULL      N/A              0             0
		MD5       HMAC-MD5        16            16
		SHA       HMAC-SHA1       20            20
		SHA256    HMAC-SHA256     32            32

		Following problems might occur: HMAC truncation.
		See
	 */

	switch(macAlg) {
		case pcpp::SSL_HASH_NULL: return 0;

		case pcpp::SSL_HASH_MD5: return 16;

		case pcpp::SSL_HASH_SHA: return 20;
		case pcpp::SSL_HASH_SHA256: return 32;
		case pcpp::SSL_HASH_SHA384: return 48;

		default: throw "Unsupported Authentication type";
	}
}


void pcapfs::Crypto::decrypt_RC4_128(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, pcpp::SSLHashingAlgorithm macAlg) {

    uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getCipherBlock().size();
    char* ciphertext = (char*) input->getCipherBlock().data();
    char* key_material = (char*) input->getKeyMaterial().data();

    // we have either md5 or sha
    const int mac_len = getMacSize(macAlg);
    const int key_len = 16;

    //unsigned char mac_key[mac_size];
    unsigned char rc4_key[key_len];

    if(input->isClientBlock) {
        //memcpy(mac_key, key_material, mac_size);
        memcpy(rc4_key, key_material + 2*mac_len, key_len);
    } else {
        //memcpy(mac_key, key_material + mac_size, mac_size);
        memcpy(rc4_key, key_material + 2*mac_len+key_len, key_len);
    }
    
	LOG_DEBUG << "entering decrypt_RC4_128 - padding: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;

    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);

    if(input->encryptThenMacEnabled)
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length - mac_len);
    else
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with padding: " << std::to_string(virtual_file_offset) << " and cipher text length: "
              << dataToDecrypt.size();


    opensslDecrypt(EVP_rc4(), rc4_key, NULL, dataToDecrypt, decryptedData);

    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + virtual_file_offset);

    //Bytes hmac_value(decryptedData);
    //hmac_value.erase(hmac_value.begin(), hmac_value.begin() + hmac_value.size() - 16);
    //output->setHmac(hmac_value);

    //Bytes plaintext(decryptedData);

    if(!input->encryptThenMacEnabled)
        //plaintext.erase(plaintext.begin() + plaintext.size() - mac_len, plaintext.begin() + plaintext.size());
        decryptedData.erase(decryptedData.end() - mac_len, decryptedData.end());
    output->setPlaintextBlock(decryptedData);
}


void pcapfs::Crypto::decrypt_AES_128_CBC(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, pcpp::SSLHashingAlgorithm macAlg) {

    //uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char*) input->getKeyMaterial().data();

    //LOG_DEBUG << "entering decrypt_AES_128_CBC - virtual file offset: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;
    
    // we have either sha or sha256
    const int mac_len = getMacSize(macAlg);
    const int key_len = 16;
    const int iv_len = 16;

    //unsigned char mac_key[mac_len];
    unsigned char aes_key[key_len];
    unsigned char iv[iv_len];

    if(input->isClientBlock) {
        //memcpy(mac_key, key_material, mac_len);
        memcpy(aes_key, key_material+2*mac_len, key_len);
        memcpy(iv, key_material+2*mac_len+2*key_len, iv_len);
    } else {
        //memcpy(mac_key, key_material+20, mac_len);
        memcpy(aes_key, key_material+2*mac_len+key_len, key_len);
        memcpy(iv, key_material+2*mac_len+2*key_len+iv_len, iv_len);
    }
    
    int cbc128_padding = 0;
    
    Bytes decryptedData;
    Bytes dataToDecrypt(0);


    if(input->encryptThenMacEnabled) {
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length - mac_len);
        decryptedData.resize(length - mac_len);
    }
    else {
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
        decryptedData.resize(length);
    }
    
    //LOG_TRACE << "decrypting with virtual file offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();

    opensslDecrypt(EVP_aes_128_cbc(), aes_key, iv, dataToDecrypt, decryptedData);

    cbc128_padding = decryptedData.back() + 1;
    LOG_TRACE << "AES CBC 128 padding len (max 16): " << cbc128_padding;

    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + iv_len);
    decryptedData.erase(decryptedData.end() - cbc128_padding, decryptedData.end());
    if(!input->encryptThenMacEnabled)
        decryptedData.erase(decryptedData.end() - mac_len, decryptedData.end());

    output->isClientBlock = input->isClientBlock;
    output->setPadding(cbc128_padding);
    output->setPlaintextBlock(decryptedData);
}


void pcapfs::Crypto::decrypt_AES_256_CBC(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, pcpp::SSLHashingAlgorithm macAlg) {    

    uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char *) input->getKeyMaterial().data();

    LOG_DEBUG << "entering decrypt_AES_256_CBC - virtual_file_offset: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;
    
    const int mac_len = getMacSize(macAlg);
    const int key_len = 32;
    const int iv_len = 16;

    unsigned char aes_key[key_len];
    unsigned char iv[iv_len];

    if(input->isClientBlock) {
        memcpy(aes_key, key_material+ 2*mac_len, key_len);
        memcpy(iv, key_material + 2*mac_len+2*key_len, iv_len);
    } else {
        memcpy(aes_key, key_material + 2*mac_len+key_len, key_len);
        memcpy(iv, key_material + 2*mac_len+2*key_len+iv_len, iv_len);
    }
    
    Bytes decryptedData;
    Bytes dataToDecrypt(0);

    if(input->encryptThenMacEnabled) {
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length - mac_len);
        decryptedData.resize(length - mac_len);
    }
    else {
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
        decryptedData.resize(length);
    }

    //TODO: what about the hmac?
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with virtual_file_offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();

    opensslDecrypt(EVP_aes_256_cbc(), aes_key, iv, dataToDecrypt, decryptedData);

    //TODO: padding?

    if(!input->encryptThenMacEnabled)
        decryptedData.erase(decryptedData.end() - mac_len, decryptedData.end());
    
    //remove the padding
    //decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    
    //decryptedData.erase(decryptedData.begin()+ plaintext_len-virtual_file_offset - 20 - 1, decryptedData.end());
    /*
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());

    printf("plaintext:\n");
    //BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset+16, plaintext_len-virtual_file_offset);
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len-virtual_file_offset);
    printf("\n\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset+16, plaintext_len-virtual_file_offset - 20 - 1);
    */
    
}

 void pcapfs::Crypto::opensslDecrypt(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, Bytes& dataToDecrypt, Bytes& decryptedData) {
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char error = 0;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
        error = 1;
    }
    
    /*
     * From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     */

    // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
    if(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0) != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1" << std::endl;
        error = 1;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);    
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1" << std::endl;
        error = 1;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    if(EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size()) != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1" << std::endl;
        error = 1;
    }
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    if(EVP_DecryptFinal_ex(ctx, decryptedData.data()+len, &len) != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1" << std::endl;
        error = 1;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    if(error)
        decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.end());
 }


void pcapfs::Crypto::decrypt_AES_256_GCM(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output) {

    uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char *) input->getKeyMaterial().data();

    unsigned char aes_key[32];
    unsigned char iv[4];

    if(input->isClientBlock) {
        memcpy(aes_key, key_material, 32);
        memcpy(iv, key_material+32, 4);
    } else {
        memcpy(aes_key, key_material+32, 32);
        memcpy(iv, key_material+32+4, 4);
    }
    
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

    unsigned char additional_data[13] = {0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x17 ,0x03 ,0x03 ,0x00 ,0x18};
    /*
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
    */
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with virtual_file_offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    /*
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, virtual_file_offset + length);
    */
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, public_nonce, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    /* Set IV length to 12 byte */
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    //return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, public_nonce);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    // Add AAD data:
    return_code = EVP_DecryptUpdate(ctx, NULL, &len, additional_data, 13);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. (AAD step) It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. (AUTH TAG) It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    /*
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len);
    */
    
    EVP_CIPHER_CTX_cleanup(ctx);
}


//See https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
void pcapfs::Crypto::decrypt_AES_128_GCM(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output) {
    
    uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char *) input->getKeyMaterial().data();

    unsigned char aes_key[16];
    unsigned char iv[4];

    if(input->isClientBlock) {
        memcpy(aes_key, key_material, 16);
        memcpy(iv, key_material+32, 4);
    } else {
        memcpy(aes_key, key_material+16, 16);
        memcpy(iv, key_material+32+4, 4);
    }

    unsigned char public_nonce[12] = {0};
    memcpy(public_nonce, iv, 4);
    memcpy(public_nonce+4, ciphertext, 8);

    unsigned char additional_data[13] = {0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x17 ,0x03 ,0x03 ,0x00 ,0x18};
    
    
    /*
     * Adjust ciphertext to reduce it by the nonce part.
     */
    
    
    
    unsigned char* auth_tag[16] = {0};
    memcpy(auth_tag, ciphertext+length-16, 16);
    
    ciphertext = ciphertext + 8;
    length = length - 8 - 16;
    /*
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
    */
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with padding " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    /*
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, virtual_file_offset + length);
    */
    
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
    return_code = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, public_nonce, 0);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    /* Set IV length to 12 byte */
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    //return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, public_nonce);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }

    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    // Add AAD data:
    return_code = EVP_DecryptUpdate(ctx, NULL, &len, additional_data, 13);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. (AAD step) It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    
    return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, auth_tag);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_CIPHER_CTX_ctrl() returned a return code != 1, 1 means success. (AUTH TAG) It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_CIPHER_CTX_ctrl() returned: " << return_code << std::endl;
    }
    
    
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    /*
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len);
    */
        
    EVP_CIPHER_CTX_cleanup(ctx);
}

