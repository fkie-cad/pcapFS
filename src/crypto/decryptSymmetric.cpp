#include "decryptSymmetric.h"
#include <string>
#include <vector>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "../logging.h"


int pcapfs::Crypto::getMacSize(const pcpp::SSLHashingAlgorithm macAlg) {

	/*
	 * https://tools.ietf.org/html/rfc5246#appendix-A.5   
     *
	 * Following problem might occur: HMAC truncation.
	 */

	switch(macAlg) {
		case pcpp::SSL_HASH_NULL: return 0;

		case pcpp::SSL_HASH_MD5: return 16;

		case pcpp::SSL_HASH_SHA: return 20;
		case pcpp::SSL_HASH_SHA256: return 32;
		case pcpp::SSL_HASH_SHA384: return 48;

		default: return -1;
	}
}


void pcapfs::Crypto::decrypt_RC4_128(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, pcpp::SSLHashingAlgorithm macAlg) {

    uint64_t virtual_file_offset = input->getVirtualFileOffset();
    size_t length = input->getCipherBlock().size();
    char* ciphertext = (char*) input->getCipherBlock().data();
    char* key_material = (char*) input->getKeyMaterial().data();

    const int mac_len = input->truncatedHmacEnabled ? 10 : getMacSize(macAlg);
    if(mac_len == -1) {
        LOG_ERROR << "Failed to decrypt a chunk because of unknown mac length" << std::endl;
        output->setPlaintextBlock(input->getCipherBlock());
        return;
    }
    const int key_len = 16;
    unsigned char rc4_key[key_len];

    if(input->isClientBlock) {
        memcpy(rc4_key, key_material + 2*mac_len, key_len);
    } else {
        memcpy(rc4_key, key_material + 2*mac_len+key_len, key_len);
    }
	LOG_DEBUG << "entering decrypt_RC4_128" << std::endl;

    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);

    if(input->encryptThenMacEnabled)
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length - mac_len);
    else
        dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with padding: " << std::to_string(virtual_file_offset) << " and cipher text length: "
              << dataToDecrypt.size();

    if(opensslDecrypt(EVP_rc4(), rc4_key, NULL, dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.end());
    } else {
        //remove the padding
        decryptedData.erase(decryptedData.begin(), decryptedData.begin() + virtual_file_offset);

        if(!input->encryptThenMacEnabled)
        decryptedData.erase(decryptedData.end() - mac_len, decryptedData.end());
    }
    output->setPlaintextBlock(decryptedData);
}


void pcapfs::Crypto::decrypt_AES_CBC(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, pcpp::SSLHashingAlgorithm macAlg, const int key_len) {

    LOG_DEBUG << "entering decrypt_AES_CBC" << std::endl;

    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char*) input->getKeyMaterial().data();

    const int mac_len = input->truncatedHmacEnabled ? 10 : getMacSize(macAlg);
    if(mac_len == -1) {
        LOG_ERROR << "Failed to decrypt a chunk because of unknown mac length" << std::endl;
        output->setPlaintextBlock(input->getCipherBlock());
        return;
    }
    const int iv_len = 16;
    Bytes aes_key(key_len);
    unsigned char iv[iv_len];

    if(input->isClientBlock) {
        memcpy(aes_key.data(), key_material+2*mac_len, key_len);
        memcpy(iv, key_material+2*mac_len+2*key_len, iv_len);
    } else {
        memcpy(aes_key.data(), key_material+2*mac_len+key_len, key_len);
        memcpy(iv, key_material+2*mac_len+2*key_len+iv_len, iv_len);
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

    if(opensslDecrypt(key_len == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), aes_key.data(), iv, dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.end());
    } else {
        // PKCS#7 padding + 1 byte
        // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2
        int padding_len = decryptedData.back() + 1;
        LOG_TRACE << "AES CBC 128 padding len: " << padding_len;

        decryptedData.erase(decryptedData.begin(), decryptedData.begin() + iv_len);
        decryptedData.erase(decryptedData.end() - padding_len, decryptedData.end());
        if(!input->encryptThenMacEnabled)
            decryptedData.erase(decryptedData.end() - mac_len, decryptedData.end());
    }
    output->setPlaintextBlock(decryptedData);
}


void pcapfs::Crypto::decrypt_AES_GCM(std::shared_ptr<CipherTextElement> input, std::shared_ptr<PlainTextElement> output, const int key_len) {
    
    LOG_DEBUG << "entering decrypt_AES_GCM" << std::endl;

    size_t length = input->getLength();
    char* ciphertext = (char *) input->getCipherBlock().data();
    char* key_material = (char *) input->getKeyMaterial().data();
    
    Bytes aes_key(key_len);
    unsigned char salt[4];

    if(input->isClientBlock) {
        memcpy(aes_key.data(), key_material, key_len);
        memcpy(salt, key_material+2*key_len, 4);
    } else {
        memcpy(aes_key.data(), key_material+key_len, key_len);
        memcpy(salt, key_material+2*key_len+4, 4);
    }

    // 96 bit gcm iv (nonce): salt (4 byte client/server_write_IV) + explicit nonce (first 8 Byte of encrypted data)
    unsigned char iv[16];
    memcpy(iv, salt, 4);
    memcpy(iv+4, ciphertext, 8);

    // expand gcm iv to ctr iv
    const unsigned char addval[4] = {0x00,0x00,0x00,0x02};
    memcpy(iv+12, addval, 4);
    
    // cut off explicit nonce part (first 8 byte of ciphertext)
    ciphertext = ciphertext + 8;

    // substract length of explicit nonce (first 8 byte) and auth tag (last 16 byte)
    length = length - 8 - 16;
    
    Bytes decryptedData(length);
    Bytes dataToDecrypt(0);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    if(opensslDecrypt(key_len == 16 ? EVP_aes_128_ctr() : EVP_aes_256_ctr(), aes_key.data(), iv, dataToDecrypt, decryptedData)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.end());
    }
    output->setPlaintextBlock(decryptedData);
}


int pcapfs::Crypto::opensslDecrypt(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, Bytes& dataToDecrypt, Bytes& decryptedData) {
    
    int error = 0;
    // From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html
     
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() generated a NULL pointer instead of a new EVP_CIPHER_CTX" << std::endl;
        error = 1;
    }

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
    
    int outlen, tmplen;
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    if(EVP_DecryptUpdate(ctx, decryptedData.data(), &outlen, dataToDecrypt.data(), dataToDecrypt.size()) != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1" << std::endl;
        error = 1;
    }
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    if(EVP_DecryptFinal_ex(ctx, decryptedData.data()+outlen, &tmplen) != 1) {
        // weird case: for 1 byte padding, the only padding byte is 0, which causes the padding to be seen as not correctly formatted
        // (condition in line 536 in evp_enc.c is true), but according to the standard, the padding is correct 
        // (see https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2)
        // => handle this case separately
        if(decryptedData.back() != 0) {
            LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1" << std::endl;
            error = 1;
        }
    }
    if(error)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_cleanup(ctx);
    return error; 
 }
