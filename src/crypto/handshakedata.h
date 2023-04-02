#ifndef PCAPFS_CRYPTO_HANDSHAKEDATA_H
#define PCAPFS_CRYPTO_HANDSHAKEDATA_H

#include <vector>
#include <cstdint>
#include <pcapplusplus/SSLLayer.h>
#include "../commontypes.h"
#include "../file.h"

namespace pcapfs {

    namespace crypto {

        size_t const CLIENT_RANDOM_SIZE = 32;
        size_t const SERVER_RANDOM_SIZE = 32;

        typedef struct TLSHandshakeData {
            TLSHandshakeData() : clientRandom(CLIENT_RANDOM_SIZE), serverRandom(SERVER_RANDOM_SIZE), rsaIdentifier(8),
                                 handshakeMessagesRaw(0), sessionHash(0), encryptedPremasterSecret(0), certificates(0),
                                 serverCertificate(0) {}
            bool processedTLSHandshake = false;
            bool clientChangeCipherSpec = false;
            bool serverChangeCipherSpec = false;
            bool encryptThenMac = false;
            bool truncatedHmac = false;
            bool extendedMasterSecret = false;
            uint64_t clientEncryptedData = 0;
	    	uint64_t serverEncryptedData = 0;
            uint16_t sslVersion = 0;
            unsigned int iteration = 0;

            Bytes clientRandom;
            Bytes serverRandom;
            Bytes rsaIdentifier;
            Bytes handshakeMessagesRaw;
            Bytes sessionHash;
            Bytes encryptedPremasterSecret;
            std::vector<FilePtr> certificates;
            Bytes serverCertificate;
            pcpp::SSLCipherSuite* cipherSuite = nullptr;
            std::string serverName;
        } TLSHandshakeData;

    }

    typedef std::shared_ptr<crypto::TLSHandshakeData> TLSHandshakeDataPtr;
}

#endif //PCAPFS_CRYPTO_HANDSHAKEDATA_H
