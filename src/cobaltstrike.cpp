#include "cobaltstrike.h"

#include <boost/beast/core/detail/base64.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto/cryptutils.h"

void pcapfs::CobaltStrike::handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort) {

    if (isKnownConnection(dstIp, dstPort) || cookie.length() <= 34)
        // when the cookie is shorter than 34 characters, the raw key can't be encoded in it
        return;

    //LOG_ERROR << "Cookie: " << cookie;

    Bytes toDecrypt(3*(cookie.length()/4) - 1); // TODO: change size of toDecrypt?
    boost::beast::detail::base64::decode(toDecrypt.data(), cookie.c_str(), cookie.length());
    //printf("toDecrypt:\n");
    //BIO_dump_fp(stdout, (const char*) toDecrypt.data(), toDecrypt.size());

    Bytes result(toDecrypt.size());
    for(const std::string &privKey : privKeyCandidates) {
        result = crypto::rsaPrivateDecrypt(toDecrypt, Bytes(privKey.begin(), privKey.end()), false);
        if (!result.empty()) {
            //printf("result:\n");
            //BIO_dump_fp(stdout, (const char*) result.data(), result.size());

            if (matchMagicBytes(result)) {
                //LOG_ERROR << "found cobalt strike communication";
                // extract symmetric key material
                Bytes rawKey(result.begin()+8, result.begin()+8+16);
                addConnectionData(rawKey, dstIp, dstPort);
            }
        }
    }
}


bool pcapfs::CobaltStrike::isKnownConnection(const std::string &ServerIp, const std::string &ServerPort) {
    return std::any_of(connections.begin(), connections.end(),
                        [ServerIp,ServerPort](const CobaltStrikeConnectionPtr &conn){ return conn->identifier() == std::make_pair(ServerIp, ServerPort); });
}


bool pcapfs::CobaltStrike::matchMagicBytes(const Bytes& input) {
    const Bytes magicBytes = {0x00, 0x00, 0xbe, 0xef};
    for (int i = 0; i < 4; ++i) {
        if (input[i] != magicBytes [i])
            return false;
    }
    return true;
}


void pcapfs::CobaltStrike::addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort) {
    Bytes digest = crypto::calculateSha256(rawKey);
    if (digest.empty())
        return;

    CobaltStrikeConnectionPtr newConnection = std::make_shared<CobaltStrikeConnection>();
    newConnection->aesKey = Bytes(digest.begin(), digest.begin()+16);
    newConnection->hmacKey = Bytes(digest.begin()+16, digest.end());
    newConnection->serverIp = dstIp;
    newConnection->serverPort = dstPort;
    connections.push_back(newConnection);

    //printf("aeskey:\n");
    //BIO_dump_fp(stdout, (const char*) newConnection->aesKey.data(), newConnection->aesKey.size());
    //printf("hmackey:\n");
    //BIO_dump_fp(stdout, (const char*) newConnection->hmacKey.data(), newConnection->hmacKey.size());
}


pcapfs::CobaltStrikeConnectionPtr pcapfs::CobaltStrike::getConnectionData(const std::string &serverIp, const std::string &serverPort) {
    CobaltStrikeConnectionPtr result;
    auto it = std::find_if(connections.cbegin(), connections.cend(),
                         [serverIp,serverPort](const CobaltStrikeConnectionPtr &conn){ return conn->identifier() == std::make_pair(serverIp, serverPort); });
    if (it != connections.cend())
        result = *it;
    return result;
}


pcapfs::Bytes const pcapfs::CobaltStrike::decryptPayload(const Bytes& input, const std::string &serverIp, const std::string &serverPort) {
    CobaltStrikeConnectionPtr conn = getConnectionData(serverIp, serverPort);
    if (input.size() < 32 || !conn)
        return input;
    
    Bytes result(input.size() - 16);
    Bytes dataToDecrypt(input.begin(), input.end()-16);
    //printf("dataToDecrypt:\n");
    //BIO_dump_fp(stdout, (const char*) dataToDecrypt.data(), dataToDecrypt.size());
    // maybe use version of openssldecrypt without decryptfinalex?
    if (opensslDecryptCS(dataToDecrypt, conn->aesKey, result)) {
        LOG_ERROR << "Failed to decrypt a chunk. Look above why" << std::endl;
        result.assign(input.begin(), input.end());
    }
    return result;
}

int pcapfs::CobaltStrike::opensslDecryptCS(const Bytes &dataToDecrypt, const Bytes &aesKey, Bytes &decryptedData) {

    int error = 0;
    // From https://www.openssl.org/docs/manmaster/man3/EVP_CIPHER_CTX_set_key_length.html

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOG_ERROR << "EVP_CIPHER_CTX_new() failed" << std::endl;
        error = 1;
    }
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, aesKey.data(), (const unsigned char*) "abcdefghijklmnop", 0) != 1) {
        LOG_ERROR << "EVP_CipherInit_ex() failed" << std::endl;
        error = 1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, aesKey.data(), (const unsigned char*) "abcdefghijklmnop") != 1) {
        LOG_ERROR << "EVP_DecryptInit_ex() failed" << std::endl;
        error = 1;
    }

    int outlen;
    if (EVP_DecryptUpdate(ctx, decryptedData.data(), &outlen, dataToDecrypt.data(), dataToDecrypt.size()) != 1) {
        LOG_ERROR << "EVP_DecryptUpdate() failed" << std::endl;
        error = 1;
    }

    //printf("decrypted:\n");
    //BIO_dump_fp(stdout, (const char*) decryptedData.data(), decryptedData.size());

    if (error)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_cleanup(ctx);
    return error;
 }
