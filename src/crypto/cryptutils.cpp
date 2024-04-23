#include "cryptutils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>


std::string const pcapfs::crypto::convertToPem(const Bytes &input) {
    X509* x509 = nullptr;
    std::string result(input.begin(), input.end());
    const unsigned char* c = input.data();

    // convert raw DER content to internal X509 structure
    x509 = d2i_X509(&x509, &c, input.size());
    if (!x509) {
        LOG_WARNING << "Openssl: Failed to read in raw tls certificate content";
        //ERR_print_errors_fp(stderr);
        X509_free(x509);
        return result;
    }

    // write x509 certificate in bio
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(bio, x509)) {
        LOG_ERROR << "Openssl: Failed to write tls certificate as pem into bio:";
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

    if ((handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_0) || (handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_1) ||
        (handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_2)) {

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
                memcpy(&seed.at(0), "extended master secret", LABEL_SIZE);
                memcpy(&seed.at(LABEL_SIZE), handshakeData->sessionHash.data(), handshakeData->sessionHash.size());
            } else {
                memcpy(&seed.at(0), "master secret", LABEL_SIZE);
                memcpy(&seed.at(LABEL_SIZE), handshakeData->clientRandom.data(), CLIENT_RANDOM_SIZE);
                memcpy(&seed.at(LABEL_SIZE + CLIENT_RANDOM_SIZE), handshakeData->serverRandom.data(), SERVER_RANDOM_SIZE);
            }
        } else {
            OUTPUT_SIZE = 192;
            memcpy(&seed.at(0), "key expansion", LABEL_SIZE);
            memcpy(&seed.at(LABEL_SIZE), handshakeData->serverRandom.data(), SERVER_RANDOM_SIZE);
            memcpy(&seed.at(LABEL_SIZE + SERVER_RANDOM_SIZE), handshakeData->clientRandom.data(), CLIENT_RANDOM_SIZE);
        }

        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr);
        if (!pctx) {
            LOG_ERROR << "Openssl: Failed to allocate public key algorithm context" << std::endl;
            ERR_print_errors_fp(stderr);
            return Bytes();
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            LOG_ERROR << "Openssl: Failed to initialize public key algorithm context" << std::endl;
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return Bytes();
        }

        if (useSha384) {
             if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha384()) <= 0) {
                LOG_ERROR << "Openssl: Failed to set the master secret" << std::endl;
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(pctx);
                return Bytes();
            }
        } else {
            if (handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_2) {
                if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
                    LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.2" << std::endl;
                    ERR_print_errors_fp(stderr);
                    EVP_PKEY_CTX_free(pctx);
                    return Bytes();
                }
            } else if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0) {
                LOG_ERROR << "Openssl: Failed to set the master secret for tls 1.0 or 1.1" << std::endl;
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(pctx);
                return Bytes();
            }
        }

        if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, input.data(), 48) <= 0) {
        	LOG_ERROR << "Openssl: PRF key derivation failed" << std::endl;
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return Bytes();
        }
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), SEED_SIZE) <= 0) {
        	LOG_ERROR << "Openssl: Failed to set the seed" << std::endl;
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return Bytes();
        }

        output.resize(OUTPUT_SIZE);
        if (EVP_PKEY_derive(pctx, output.data(), &OUTPUT_SIZE) <= 0) {
        	LOG_ERROR << "Openssl: Failed to derive the shared secret" << std::endl;
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(pctx);
            return Bytes();
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

    // write RSA private key to BIO
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, rsaPrivateKey.data(), rsaPrivateKey.size());
    if(!bio) {
        if (printErrors) {
            LOG_ERROR << "Openssl: Failed to create BIO with rsa private key";
            ERR_print_errors_fp(stderr);
        }
        BIO_free(bio);
        return result;
    }

    // decode RSA private key from BIO to EVP_PKEY format
    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", nullptr, "RSA", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
    if (!dctx) {
        if (printErrors) {
            LOG_ERROR << "Openssl: Failed to init decoder for rsa private key";
            ERR_print_errors_fp(stderr);
        }
        BIO_free(bio);
        return result;
    }
    if (!OSSL_DECODER_from_bio(dctx, bio)) {
        if (printErrors) {
            LOG_ERROR << "Openssl: Failed to decode rsa private key from BIO";
            ERR_print_errors_fp(stderr);
        }
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return result;
    }

    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);

    // prepare decryption
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        if (printErrors) {
            LOG_ERROR << "Openssl: Failed to set RSA decryption context";
            ERR_print_errors_fp(stderr);
        }
        EVP_PKEY_free(pkey);
        return result;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        if (printErrors) {
            LOG_ERROR << "Openssl: Failed to init RSA decryption context";
            ERR_print_errors_fp(stderr);
        }
        EVP_PKEY_free(pkey);
        return result;
    }

    size_t outlen;
    const std::vector<int> possible_padding = {RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_NO_PADDING};
    for(size_t i = 0; i < possible_padding.size(); ++i) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, possible_padding[i]) <= 0) {
            if (i == possible_padding.size() - 1) {
                if (printErrors) {
                    LOG_ERROR << "Openssl: Failed to decrypt encrypted premaster secret";
                    ERR_print_errors_fp(stderr);
                }
                result.clear();
                break;
            } else
                continue;
        }
        // determine output length
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, input.data(), input.size()) <= 0) {
            if (i == possible_padding.size() - 1) {
                if (printErrors) {
                    LOG_ERROR << "Openssl: Failed to decrypt encrypted premaster secret";
                    ERR_print_errors_fp(stderr);
                }
                result.clear();
                break;
            } else
                continue;
        }
        // actual decryption
        result.resize(outlen);
        if (EVP_PKEY_decrypt(ctx, result.data(), &outlen, input.data(), input.size()) <= 0) {
            if (i == possible_padding.size() - 1) {
                if (printErrors) {
                    LOG_ERROR << "Openssl: Failed to decrypt encrypted premaster secret";
                    ERR_print_errors_fp(stderr);
                }
                result.clear();
                break;
            }
        } else
            break;
    }

    EVP_PKEY_free(pkey);
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

    // decode RSA private key from BIO to EVP_PKEY format
    EVP_PKEY *privKey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&privKey, "PEM", nullptr, "RSA", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
    if (!dctx) {
        LOG_ERROR << "Openssl: Failed to init decoder for rsa private key";
        BIO_free(bio);
        return false;
    }
    if (!OSSL_DECODER_from_bio(dctx, bio)) {
        LOG_ERROR << "Openssl: Failed to decode rsa private key from BIO";
        OSSL_DECODER_CTX_free(dctx);
        EVP_PKEY_free(privKey);
        BIO_free(bio);
        return false;
    }

    OSSL_DECODER_CTX_free(dctx);
    BIO_free(bio);

    const unsigned char* c = serverCertificate.data();
    X509* x509 = nullptr;
    x509 = d2i_X509(&x509, &c, serverCertificate.size());
    if (!x509) {
        LOG_ERROR << "Openssl: Failed to read in raw tls certificate content";
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

    if((handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_0) || (handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_1) ||
        (handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_2)) {

        bool useSha384 = (handshakeData->cipherSuite->getMACAlg() == pcpp::SSL_HASH_SHA384) ? true : false;

        EVP_MD_CTX *mdctx;
        unsigned int digest_len = 0;
	    if((mdctx = EVP_MD_CTX_new()) == nullptr) {
            LOG_ERROR << "Openssl: failed to set digest context";
            ERR_print_errors_fp(stderr);
            return Bytes();
        }

        if(useSha384){
            digest.resize(48);
            digest_len = 48;
	        if(EVP_DigestInit_ex(mdctx, EVP_sha384(), nullptr) != 1) {
                LOG_ERROR << "Openssl: failed to init digest context";
                ERR_print_errors_fp(stderr);
                EVP_MD_CTX_free(mdctx);
                return Bytes();
            }
        } else {
            if(handshakeData->tlsVersion == pcpp::SSLVersion::TLS1_2){
                digest.resize(32);
                digest_len = 32;
                if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                    LOG_ERROR << "Openssl: failed to init digest context";
                    ERR_print_errors_fp(stderr);
                    EVP_MD_CTX_free(mdctx);
                    return Bytes();
                }
            } else {
                digest.resize(36);
                digest_len = 36;
                if(EVP_DigestInit_ex(mdctx, EVP_md5_sha1(), nullptr) != 1) {
                    LOG_ERROR << "Openssl: failed to init digest context";
                    ERR_print_errors_fp(stderr);
                    EVP_MD_CTX_free(mdctx);
                    return Bytes();
                }
            }
        }

	    if(EVP_DigestUpdate(mdctx, handshakeData->handshakeMessagesRaw.data(), handshakeData->handshakeMessagesRaw.size()) != 1) {
            LOG_ERROR << "Openssl: EVP_DigestUpdate() failed";
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(mdctx);
            return Bytes();
        }
	    if(EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len) != 1) {
            LOG_ERROR << "Openssl: EVP_DigestFinal_ex() failed";
            ERR_print_errors_fp(stderr);
            EVP_MD_CTX_free(mdctx);
            return Bytes();
        }

	    EVP_MD_CTX_free(mdctx);
    } else {
        LOG_ERROR << "TLS version not supported for decryption" << std::endl;
    }

    return digest;
}


pcapfs::Bytes const pcapfs::crypto::calculateSha256(const Bytes &input) {

    unsigned int digest_len = 32;
    Bytes digest(digest_len);

    EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_new()) == nullptr) {
        LOG_ERROR << "Failed to derive symmetric Key Material for Cobalt Strike decryption:";
        LOG_ERROR << "Openssl: failed to set digest context";
        ERR_print_errors_fp(stderr);
        return Bytes();
    }
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        LOG_ERROR << "Failed to derive symmetric Key Material for Cobalt Strike decryption:";
        LOG_ERROR << "Openssl: failed to init digest context";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return Bytes();
    }
    if(EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1) {
        LOG_ERROR << "Failed to derive symmetric Key Material for Cobalt Strike decryption:";
        LOG_ERROR << "Openssl: EVP_DigestUpdate() failed";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return Bytes();
    }
	if(EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len) != 1) {
        LOG_ERROR << "Failed to derive symmetric Key Material for Cobalt Strike decryption:";
        LOG_ERROR << "Openssl: EVP_DigestFinal_ex() failed";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return Bytes();
    }

    return digest;
}


std::string const pcapfs::crypto::calculateSha256AsString(const std::string &input) {
    std::ostringstream sout;
    for(int  c: calculateSha256(Bytes(input.begin(), input.end())))
        sout << std::hex << std::setw(2) << std::setfill('0') << c;
    return sout.str();
}


std::string const pcapfs::crypto::calculateMD5(const std::string &input) {
    unsigned int digestLen = MD5_DIGEST_LENGTH;
    unsigned char digest[MD5_DIGEST_LENGTH];

    EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_new()) == nullptr) {
        LOG_ERROR << "Failed to to calculate MD5 hash:";
        LOG_ERROR << "Openssl: failed to set digest context";
        ERR_print_errors_fp(stderr);
        return std::string();
    }
    if(EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        LOG_ERROR << "Failed to to calculate MD5 hash:";
        LOG_ERROR << "Openssl: failed to init digest context";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return std::string();
    }
    if(EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1) {
        LOG_ERROR << "Failed to to calculate MD5 hash:";
        LOG_ERROR << "Openssl: EVP_DigestUpdate() failed";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return std::string();
    }
	if(EVP_DigestFinal_ex(mdctx, digest, &digestLen) != 1) {
        LOG_ERROR << "Failed to to calculate MD5 hash:";
        LOG_ERROR << "Openssl: EVP_DigestFinal_ex() failed";
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return std::string();
    }

	EVP_MD_CTX_free(mdctx);

    std::ostringstream sout;
    sout << std::hex << std::setfill('0');
    for(long long  c: digest)
        sout << std::setw(2) << (long long)c;
    return sout.str();
}


bool pcapfs::crypto::loadLegacyProvider() {
    if (OSSL_PROVIDER_available(nullptr, "legacy"))
        return true;

    OSSL_PROVIDER *legacy;
    OSSL_PROVIDER *deflt;

    legacy = OSSL_PROVIDER_load(nullptr, "legacy");
    if (!legacy) {
        LOG_ERROR << "Openssl: failed to load legacy provider";
        return false;
    }

    // Once the legacy provider is explicitly loaded into the library context,
    // we also need to explicitly load the default provider
    deflt = OSSL_PROVIDER_load(nullptr, "default");
    if (!deflt) {
        LOG_ERROR << "Openssl: failed to load default provider";
        return false;
    }

    LOG_DEBUG << "loaded legacy provider";
    return true;
}
