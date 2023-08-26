#ifndef PCAPFS_CRYPTO_CRYPTUTILS_H
#define PCAPFS_CRYPTO_CRYPTUTILS_H

#include <string>
#include "handshakedata.h"
#include "../commontypes.h"


namespace pcapfs {

    namespace crypto {

        std::string const convertToPem(const Bytes &input);

        Bytes const createKeyMaterial(const Bytes &input, const TLSHandshakeDataPtr &handshakeData, bool deriveMasterSecret);

        Bytes const calculateSessionHash(const TLSHandshakeDataPtr &handshakeData);

        Bytes const rsaPrivateDecrypt(const Bytes &input, const Bytes &rsaPrivateKey, bool printErrors);

        int matchPrivateKey(const Bytes &rsaPrivateKey, const Bytes &serverCertificate);

        Bytes const calculateSha256(const Bytes &input);

        std::string const calculateMD5(const std::string &input);

    }
}

#endif // PCAPFS_CRYPTO_CRYPTUTILS_H
