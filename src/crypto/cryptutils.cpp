#include "cryptutils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


std::string const pcapfs::crypto::convertToPem(const Bytes &input) {
    X509* x509 = nullptr;
    std::string result(input.begin(), input.end());
    const unsigned char* c = input.data();

    // convert raw DER content to internal X509 structure
    x509 = d2i_X509(&x509, &c, input.size());
    if (!x509) {
        LOG_WARNING << "Openssl: Failed to read in raw ssl certificate content";
        //ERR_print_errors_fp(stderr);
        X509_free(x509);
        return result;
    }

    // write x509 certificate in bio
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(bio, x509)) {
        LOG_ERROR << "Openssl: Failed to write ssl certificate as pem into bio:";
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        X509_free(x509);
        return result;
    }

    // access certificate content in bio
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if(!mem || !mem->data || !mem->length) {
        LOG_ERROR << "Openssl: Failed to extract buffer out of bio:";
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        X509_free(x509);
        return result;
    }

    result.assign(mem->data, mem->length);

    BIO_free(bio);
    X509_free(x509);
    return result;
}


pcapfs::Bytes const pcapfs::crypto::createKeyMaterial(const Bytes &input, const TLSHandshakeDataPtr &handshakeData, bool deriveMasterSecret) {

    //function to derive the master secret from premaster secret and derive key material from master secret
    /*
     * SSLv3:
     *
     * It is a bit longer, see this one:
     *
     * https://tools.ietf.org/html/rfc6101#section-6.2.1
     *
     *
     * TLS 1.0 and TLS 1.1:
     *          PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
     *                                      P_SHA-1(S2, label + seed);
     *
     * TLS 1.2:
     *       PRF(secret, label, seed) = P_SHA256(secret, label + seed)
     *
     *
     *
     * key_block = PRF(SecurityParameters.master_secret,
     *                 "key expansion",
     *                 SecurityParameters.server_random +
     *                 SecurityParameters.client_random);
     *
     * KEY MATERIAL (TLS 1.0/1.1/1.2):
     *          client_write_MAC_secret[SecurityParameters.hash_size]
     *          server_write_MAC_secret[SecurityParameters.hash_size]
     *          client_write_key[SecurityParameters.key_material_length]
     *          server_write_key[SecurityParameters.key_material_length]
     *          client_write_IV[SecurityParameters.IV_size]
     *          server_write_IV[SecurityParameters.IV_size]
     */

    Bytes output(0);

    if (input.empty())
        return output;

    if ((handshakeData->sslVersion == pcpp::SSLVersion::TLS1_0) || (handshakeData->sslVersion == pcpp::SSLVersion::TLS1_1) ||
        (handshakeData->sslVersion == pcpp::SSLVersion::TLS1_2)) {

        if (handshakeData->clientRandom.empty() || handshakeData->serverRandom.empty()) {
            LOG_ERROR << "Failed to derive key material because client and/or server random could not be extracted";
            return output;
        }

        bool useSha384 = (handshakeData->cipherSuite->getMACAlg() == pcpp::SSL_HASH_SHA384) ? true : false;

        size_t LABEL_SIZE = 13;
        size_t SEED_SIZE = LABEL_SIZE + CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE;
        Bytes seed(SEED_SIZE);

        size_t OUTPUT_SIZE;
        if (deriveMasterSecret){
            OUTPUT_SIZE = 48;
            if (handshakeData->extendedMasterSecret) {
                if (handshakeData->sessionHash.empty()) {
                    LOG_ERROR << "Failed to derive extended master secret because session hash could not be calculated";
                    return output;
                }
                LABEL_SIZE = 22;
                SEED_SIZE = LABEL_SIZE + handshakeData->sessionHash.size();
                seed.resize(SEED_SIZE);
                memcpy(&seed[0], "extended master secret", LABEL_SIZE);
                memcpy(&seed[LABEL_SIZE], handshakeData->sessionHash.data(), handshakeData->sessionHash.size());
            } else {
                memcpy(&seed[0], "master secret", LABEL_SIZE);
                memcpy(&seed[LABEL_SIZE], handshakeData->clientRandom.data(), CLIENT_RANDOM_SIZE);
                memcpy(&seed[LABEL_SIZE + CLIENT_RANDOM_SIZE], handshakeData->serverRandom.data(), SERVER_RANDOM_SIZE);
            }
        } else {
            OUTPUT_SIZE = 192;
            memcpy(&seed[0], "key expansion", LABEL_SIZE);
            memcpy(&seed[LABEL_SIZE], handshakeData->serverRandom.data(), SERVER_RANDOM_SIZE);
            memcpy(&seed[LABEL_SIZE + SERVER_RANDOM_SIZE], handshakeData->clientRandom.data(), CLIENT_RANDOM_SIZE);
        }

        unsigned char error = 0;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr);
        if (!pctx) {
            LOG_ERROR << "Openssl: Failed to allocate public key algorithm context" << std::endl;
            error = 1;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            LOG_ERROR << "Openssl: Failed to initialize public key algorithm context" << std::endl;
            error = 1;
        }

        if (useSha384) {
             if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha384()) <= 0) {
                    LOG_ERROR << "Openssl: Failed to set the master secret" << std::endl;
                    error = 1;
                }
        } else {
            if (handshakeData->sslVersion == pcpp::SSLVersion::TLS1_2) {
                if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
                    LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.2" << std::endl;
                    error = 1;
                }
            } else if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0) {
                LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.0 or 1.1" << std::endl;
                error = 1;
            }
        }

        if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, input.data(), 48) <= 0) {
        	LOG_ERROR << "Openssl: PRF key derivation failed" << std::endl;
            error = 1;
        }
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), SEED_SIZE) <= 0) {
        	LOG_ERROR << "Openssl: Failed to set the seed" << std::endl;
            error = 1;
        }

        output.resize(OUTPUT_SIZE);
        if (EVP_PKEY_derive(pctx, output.data(), &OUTPUT_SIZE) <= 0) {
        	LOG_ERROR << "Openssl: Failed to derive the shared secret" << std::endl;
            error = 1;
        }

        if (error) {
            ERR_print_errors_fp(stderr);
            output.clear();
        }

        EVP_PKEY_CTX_free(pctx);

    } else {
        LOG_ERROR << "TLS/SSL version not supported for decryption" << std::endl;
    }

    return output;
}


pcapfs::Bytes const pcapfs::crypto::rsaPrivateDecrypt(const Bytes &input, const Bytes &rsaPrivateKey, bool printErrors) {

    Bytes result(0);

    if(input.empty() || rsaPrivateKey.empty()) {
        if (printErrors)
            LOG_ERROR << "Failed to decrypt encrypted premaster secret";
        return result;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, rsaPrivateKey.data(), rsaPrivateKey.size());
    if(!bio) {
        if (printErrors)
            LOG_ERROR << "Openssl: Failed to create BIO with rsa private key";
        BIO_free(bio);
        return result;
    }

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if(!rsa) {
        if (printErrors)
            LOG_ERROR << "Openssl: Failed to read in rsa private key";
        BIO_free(bio);
        return result;
    }

    BIO_free(bio);

    result.resize(RSA_size(rsa));
    std::vector<int> possible_padding = {RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_NO_PADDING};
    for(size_t i = 0; i < possible_padding.size(); ++i) {
        if(RSA_private_decrypt(input.size(), input.data(),
                                result.data(), rsa, possible_padding[i]) != -1) {
            break;

        } else if(i == possible_padding.size() - 1) {
            if (printErrors)
                LOG_ERROR << "Openssl: Failed to decrypt encrypted premaster secret";
            result.clear();
        }
    }
    RSA_free(rsa);

    return result;
}


int pcapfs::crypto::matchPrivateKey(const Bytes &rsaPrivateKey, const Bytes &serverCertificate) {
    if(rsaPrivateKey.empty() || serverCertificate.empty()) {
        return false;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, rsaPrivateKey.data(), rsaPrivateKey.size());
    if(!bio) {
        LOG_ERROR << "Openssl: Failed to create BIO with rsa private key";
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return false;
    }

    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if(!privKey) {
        LOG_ERROR << "Openssl: Failed to read in rsa private key";
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        EVP_PKEY_free(privKey);
        return false;
    }

    BIO_free(bio);

    const unsigned char* c = serverCertificate.data();
    X509* x509 = nullptr;
    x509 = d2i_X509(&x509, &c, serverCertificate.size());
    if (!x509) {
        LOG_ERROR << "Openssl: Failed to read in raw ssl certificate content";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(privKey);
        X509_free(x509);
        return false;
    }

    int result = X509_verify(x509, privKey);

    X509_free(x509);
    EVP_PKEY_free(privKey);

    return result;
}


pcapfs::Bytes const pcapfs::crypto::calculateSessionHash(const TLSHandshakeDataPtr &handshakeData) {

    Bytes digest(0);

    if((handshakeData->sslVersion == pcpp::SSLVersion::TLS1_0) || (handshakeData->sslVersion == pcpp::SSLVersion::TLS1_1) ||
        (handshakeData->sslVersion == pcpp::SSLVersion::TLS1_2)) {

        bool useSha384 = (handshakeData->cipherSuite->getMACAlg() == pcpp::SSL_HASH_SHA384) ? true : false;

        EVP_MD_CTX *mdctx;
        unsigned int digest_len = 0;
        unsigned char error = 0;
	    if((mdctx = EVP_MD_CTX_new()) == nullptr)
	    	error = 1;

        if(useSha384){
            digest.resize(48);
            digest_len = 48;
	        if(EVP_DigestInit_ex(mdctx, EVP_sha384(), nullptr) != 1)
	    	    error = 1;
        } else {
            if(handshakeData->sslVersion == pcpp::SSLVersion::TLS1_2){
                digest.resize(32);
                digest_len = 32;
                if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
	    	        error = 1;
            } else {
                digest.resize(36);
                digest_len = 36;
                if(EVP_DigestInit_ex(mdctx, EVP_md5_sha1(), nullptr) != 1)
                    error = 1;
            }
        }

	    if(EVP_DigestUpdate(mdctx, handshakeData->handshakeMessagesRaw.data(), handshakeData->handshakeMessagesRaw.size()) != 1)
	    	error = 1;

	    if(EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len) != 1)
	    	error = 1;

        if(error) {
            ERR_print_errors_fp(stderr);
            digest.clear();
        }

	    EVP_MD_CTX_free(mdctx);
    } else {
        LOG_ERROR << "TLS/SSL version not supported for decryption" << std::endl;
    }

    return digest;
}


pcapfs::Bytes const pcapfs::crypto::calculateSha256(const Bytes &input) {

    unsigned int digest_len = 32;
    Bytes digest(digest_len);

    EVP_MD_CTX *mdctx;
    unsigned char error = 0;
	if((mdctx = EVP_MD_CTX_new()) == nullptr)
		error = 1;
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
	    error = 1;
    if(EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1)
	    error = 1;
	if(EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len) != 1)
		error = 1;

    if(error) {
        LOG_ERROR << "Failed to derive symmetric Key Material for Cobalt Strike decryption";
        ERR_print_errors_fp(stderr);
        digest.clear();
    }

	EVP_MD_CTX_free(mdctx);

    return digest;
}
