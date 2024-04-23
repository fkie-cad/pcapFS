#ifndef PCAPFS_CRYPTO_HANDSHAKEDATA_H
#define PCAPFS_CRYPTO_HANDSHAKEDATA_H

#include <vector>
#include <cstdint>
#include <set>
#include <pcapplusplus/SSLLayer.h>
#include "../commontypes.h"
#include "../file.h"

namespace pcapfs {

    namespace crypto {

        size_t const CLIENT_RANDOM_SIZE = 32;
        size_t const SERVER_RANDOM_SIZE = 32;

        const std::unordered_map<uint16_t, std::string> tlsVersionMap = {
                {pcpp::SSLVersion::SSL2, "s2"},
                {pcpp::SSLVersion::SSL3, "s3"},
                {pcpp::SSLVersion::TLS1_0, "10"},
                {pcpp::SSLVersion::TLS1_1, "11"},
                {pcpp::SSLVersion::TLS1_2, "12"},
                {pcpp::SSLVersion::TLS1_3, "13"}
        };

        const std::set<uint16_t> tlsGreaseValues = {
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
                0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                0xcaca, 0xdada, 0xeaea, 0xfafa
        };

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
            uint16_t tlsVersion = 0;
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
            std::string ja3;
            std::string ja3s;
            std::string ja4;
        } TLSHandshakeData;

    }

    typedef std::shared_ptr<crypto::TLSHandshakeData> TLSHandshakeDataPtr;
}

#endif //PCAPFS_CRYPTO_HANDSHAKEDATA_H
