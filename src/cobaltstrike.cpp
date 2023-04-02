#include "cobaltstrike.h"

#include <boost/beast/core/detail/base64.hpp>
#include <openssl/bio.h>
#include "crypto/cryptutils.h"

void pcapfs::CobaltStrike::handleHttpGet(const std::string &cookie) {

    if (std::find(knownCookies.begin(), knownCookies.end(), cookie) != knownCookies.end())
        return;
    
    knownCookies.push_back(cookie);
    LOG_ERROR << "Cookie: " << cookie;

    Bytes toDecrypt(3*(cookie.length()/4) - 1); // TODO: change size of toDecrypt?
    boost::beast::detail::base64::decode(toDecrypt.data(), cookie.c_str(), cookie.length());
    printf("toDecrypt:\n");
    BIO_dump_fp(stdout, (const char*) toDecrypt.data(), toDecrypt.size());

    Bytes result(toDecrypt.size());
    for(const std::string &privKey : privKeyCandidates) {
        result = crypto::rsaPrivateDecrypt(toDecrypt, Bytes(privKey.begin(), privKey.end()), false);
        if (!result.empty()) {
            printf("result:\n");
            BIO_dump_fp(stdout, (const char*) result.data(), result.size());

            if (matchMagicBytes(result)) {
                LOG_ERROR << "found cobalt strike communication";
                // extract symmetric key material
            }
        }
    }
}


bool pcapfs::CobaltStrike::matchMagicBytes(const Bytes& input) {
    const Bytes magicBytes = {0x00, 0x00, 0xbe, 0xef};
    for (int i = 0; i < 4; ++i) {
        if (input[i] != magicBytes [i])
            return false;
    }
    return true;
}