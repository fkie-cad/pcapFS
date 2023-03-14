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

        Bytes const decryptPreMasterSecret(const Bytes &encryptedPremasterSecret, const Bytes &rsaPrivateKey);

        int matchPrivateKey(const Bytes &rsaPrivateKey, const Bytes &serverCertificate);

    }
}

#endif // PCAPFS_CRYPTO_CRYPTUTILS_H