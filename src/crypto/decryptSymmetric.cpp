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

size_t pcapfs::Crypto::getMacSize(pcpp::SSLVersion sslVersion, std::string cipherSuite) {

	pcpp::SSLCipherSuite *cipher_suite = pcpp::SSLCipherSuite::getCipherSuiteByName(cipherSuite);

	if(cipher_suite == NULL) {
		return -1;
	}

	pcpp::SSLHashingAlgorithm hash_algorithm = cipher_suite->getMACAlg();

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

	switch(hash_algorithm) {
		case pcpp::SSL_HASH_NULL: return 0;

		case pcpp::SSL_HASH_MD5: return 16;

		case pcpp::SSL_HASH_SHA: return 20;
		case pcpp::SSL_HASH_SHA256: return 32;
		case pcpp::SSL_HASH_SHA384: return 48;

		/*
		 * Unsupported yet
		 */

		case pcpp::SSL_HASH_GOST28147: throw "Unsupported Authentication type";
		case pcpp::SSL_HASH_GOSTR3411: throw "Unsupported Authentication type";

		case pcpp::SSL_HASH_CCM: throw "Unsupported Authentication type";
		case pcpp::SSL_HASH_CCM_8: throw "Unsupported Authentication type";

		case pcpp::SSL_HASH_Unknown: throw "Unsupported Authentication type";
	}

	throw "Unsupported Authentication type";
}

void pcapfs::Crypto::decrypt_RC4_128(
		uint64_t virtual_file_offset,
		size_t length,
		char *ciphertext,
		unsigned char *mac,
		unsigned char *key,
		bool isClientMessage,
		pcapfs::PlainTextElement *output
	) {
    
	LOG_DEBUG << "entering decrypt_RC4_128 - padding: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;

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
    printf("HMAC SHA256: %i\n", pcpp::SSLHashingAlgorithm::SSL_HASH_SHA256);

    printf("------------------------------------------------------------------------------------------------\n");

    if(isClientMessage) {
    	printf("CLIENT\n");
    } else {
    	printf("SERVER\n");
    }
    
    printf("------------------------------------------------------------------------------------------------\n");
    printf("padding bytes: %li\n", padding);
    printf("length: %li\n", length);
    printf("mac_key:\n");
    BIO_dump_fp (stdout, (const char *)mac, 16);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *)key, 16);
    printf("ciphertext without padding:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, length);
    printf("------------------------------------------------------------------------------------------------\n");
	*/


    int return_code = 0;

    int len = 0;
    int plaintext_len = 0;

    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    LOG_TRACE << "decrypting with padding: " << std::to_string(virtual_file_offset) << " and cipher text length: "
              << dataToDecrypt.size();

    //decrypt data using keys and RC4
    unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    unsigned char *rc4_key = reinterpret_cast<unsigned char *>(key);

    /*
    printf("key:\n");
    BIO_dump_fp(stdout, (const char *) rc4_key, 16);

    printf("ciphertext:\n");
    BIO_dump_fp(stdout, (const char *) dataToDecrypt.data(), dataToDecrypt.size());
     */

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
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

    if (return_code != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code
                  << std::endl;
    } else {
    	LOG_TRACE << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }

    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4_key, NULL);

    if (return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code
                  << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }

    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());

    if (return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code
                  << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }

    plaintext_len = len;

    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);

    if (return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code
                  << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }

    plaintext_len += len;

    LOG_DEBUG << "plaintext_len after decrypt_final decryption: " << plaintext_len << std::endl;

    //remove the padding
    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + virtual_file_offset);

    //std::string decryptedContent(decryptedData.begin(), decryptedData.end());

    //printf("plaintext:\n");
    //BIO_dump_fp(stdout, (const char *) decryptedData.data(), plaintext_len - padding );

    Bytes hmac_value(decryptedData);
    hmac_value.erase(hmac_value.begin(), hmac_value.begin() + hmac_value.size() - 16);
    output->hmac = hmac_value;

    Bytes plaintext(decryptedData);
    plaintext.erase(plaintext.begin() + plaintext.size() - 16, plaintext.begin() + plaintext.size());
    output->plaintextBlock = plaintext;

    EVP_CIPHER_CTX_cleanup(ctx);
}

void pcapfs::Crypto::decrypt_AES_128_CBC(
		uint64_t virtual_file_offset,
		size_t length,
		char *ciphertext,
		unsigned char *mac,
		unsigned char *key,
		unsigned char *iv,
		bool isClientMessage,
		pcapfs::PlainTextElement *output
	) {
    
	pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");

	/*
	 * AES CBC Mode for TLS 1.1:
	 *
	 * ciphertext has this structure:
	 *
	 * actual ciphertext
	 * MAC (20 bytes)
	 *
	 * The mac is used to check the ciphertext!
	 *
	 * The decrypted stuff looks like this:
	 *
	 * 16 byte IV (? not sure if these bytes are actually the IV for next packets)
	 *
	 */

    LOG_DEBUG << "entering decrypt_AES_128_CBC - virtual file offset: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;
    
    //TODO: get log level during runtime, print when trace
    if (1==0) {
		printf("mac_key:\n");
		BIO_dump_fp (stdout, (const char *) mac, 20);
		printf("key:\n");
		BIO_dump_fp (stdout, (const char *) key, 16);
		printf("iv:\n");
		BIO_dump_fp (stdout, (const char *) iv, 16);
    }
    
    int cbc128_padding = 0;
    const int iv_len = 16;
    int mac_len = 20;
    const int ciphertext_len_calculated = length - mac_len;

    int return_code, len, plaintext_len;
    
    Bytes decryptedData(ciphertext_len_calculated);
    std::fill(decryptedData.begin(), decryptedData.end(), 0);

    Bytes mac_from_ciphertext(0);
    mac_from_ciphertext.insert(mac_from_ciphertext.end(), ciphertext + ciphertext_len_calculated, ciphertext + ciphertext_len_calculated + mac_len);

    Bytes dataToDecrypt(0);
    

    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + ciphertext_len_calculated);
    
    LOG_TRACE << "decrypting with virtual file offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    if (1==0) {
		printf("ciphertext:\n");
		BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, dataToDecrypt.size());
	}

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
    	LOG_TRACE << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the virtual_file_offset
    //decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);

    //decryptedData.erase(decryptedData.begin()+ plaintext_len-padding - 20 - 1, decryptedData.end());

    //std::string decryptedContent(decryptedData.begin(), decryptedData.end());

    /*
     * get last byte, contains the padding length.
     * you need to add one to the byte. when padding would not be necessary we add 16 (0x0f) (plus one, -> 16).
     */

    // MAC SIZE IS 20 byte

    cbc128_padding = decryptedData.back() + 1;
    LOG_TRACE << "AES CBC 128 padding len (max 16): " << cbc128_padding;

    if (1==0) {
    	printf("plaintext: plaintext_len %zu  decryptedData.size() %zu\n", plaintext_len, decryptedData.size());
    	BIO_dump_fp (stdout, (const char *)decryptedData.data() + iv_len, decryptedData.size() - iv_len - cbc128_padding);
    	printf("\n\n");
    }

    /*
     * Warning: This hmac is actually useless, it should verify the ciphertext only!
     */
    output->hmac = mac_from_ciphertext;

    decryptedData.erase(decryptedData.begin(), decryptedData.begin() + iv_len);
    decryptedData.erase(decryptedData.end() - cbc128_padding, decryptedData.end());

    output->isClientBlock = isClientMessage;
    output->padding = cbc128_padding;
    output->plaintextBlock = decryptedData;

    EVP_CIPHER_CTX_cleanup(ctx);
    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "entered");
}

void pcapfs::Crypto::decrypt_AES_256_CBC(
		uint64_t virtual_file_offset,
		size_t length,
		char *ciphertext,
		unsigned char *mac,
		unsigned char *key,
		unsigned char *iv,
		bool isClientMessage,
		pcapfs::PlainTextElement *output
	) {
    
    LOG_DEBUG << "entering decrypt_AES_256_CBC - virtual_file_offset: " << std::to_string(virtual_file_offset) << " length: " << std::to_string(length)  << std::endl;
    
    printf("mac_key:\n");
    BIO_dump_fp (stdout, (const char *) mac, 20);
    printf("key:\n");
    BIO_dump_fp (stdout, (const char *) key, 32);
    printf("iv:\n");
    BIO_dump_fp (stdout, (const char *) iv, 16);
    
    int return_code, len, plaintext_len;
    
    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with virtual_file_offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
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
    	LOG_TRACE << "EVP_CipherInit_ex() returned: " << return_code << std::endl;
    }
    
    //int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
    return_code = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptInit_ex() return code: " << return_code << std::endl;
    }
    
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    return_code = EVP_DecryptUpdate(ctx, decryptedData.data(), &len, dataToDecryptPtr, dataToDecrypt.size());
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptUpdate() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len = len;
    
    //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
    return_code = EVP_DecryptFinal_ex(ctx, decryptedData.data()+ len, &len);
    
    if(return_code != 1) {
        LOG_ERROR << "EVP_DecryptFinal_ex() returned a return code != 1, 1 means success. It returned: " << return_code << std::endl;
    } else {
    	LOG_TRACE << "EVP_DecryptFinal_ex() return code: " << return_code << " , len now: " << len << std::endl;
    }
    
    plaintext_len += len;
    
    //remove the padding
    //decryptedData.erase(decryptedData.begin(), decryptedData.begin() + padding + 16);
    
    //decryptedData.erase(decryptedData.begin()+ plaintext_len-virtual_file_offset - 20 - 1, decryptedData.end());
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    //BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset+16, plaintext_len-virtual_file_offset);
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len-virtual_file_offset);
    printf("\n\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset+16, plaintext_len-virtual_file_offset - 20 - 1);
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
}


void pcapfs::Crypto::decrypt_AES_256_GCM(
		uint64_t virtual_file_offset,
		size_t length,
		char *ciphertext,
		unsigned char *mac,
		unsigned char *key,
		unsigned char *iv,
		unsigned char *additional_data,
		bool isClientMessage,
		PlainTextElement *output
	) {
    
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
    
    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with virtual_file_offset " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, virtual_file_offset + length);
    
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
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, public_nonce);
    
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
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len);
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
}

//See https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
void pcapfs::Crypto::decrypt_AES_128_GCM(
		uint64_t virtual_file_offset,
		size_t length,
		char *ciphertext,
		unsigned char *mac,
		unsigned char *key,
		unsigned char *iv,
		unsigned char *additional_data,
		bool isClientMessage,
		PlainTextElement *output
	) {

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
    
    Bytes decryptedData(virtual_file_offset + length);
    Bytes dataToDecrypt(virtual_file_offset);
    
    dataToDecrypt.insert(dataToDecrypt.end(), ciphertext, ciphertext + length);
    
    LOG_TRACE << "decrypting with padding " << std::to_string(virtual_file_offset) << " of length " << dataToDecrypt.size();
    
    const unsigned char *dataToDecryptPtr = reinterpret_cast<unsigned char *>(dataToDecrypt.data());
    
    printf("ciphertext:\n");
    BIO_dump_fp (stdout, (const char *) dataToDecryptPtr, virtual_file_offset + length);
    
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
    return_code = EVP_DecryptInit_ex(ctx, NULL, NULL, key, public_nonce);
    
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
    
    std::string decryptedContent(decryptedData.begin(), decryptedData.end());
    
    printf("plaintext:\n");
    BIO_dump_fp (stdout, (const char *)decryptedData.data() + virtual_file_offset, plaintext_len);
    
        
    EVP_CIPHER_CTX_cleanup(ctx);
}

