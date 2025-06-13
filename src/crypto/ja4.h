#ifndef PCAPFS_JA4_H
#define PCAPFS_JA4_H

#include "../commontypes.h"
#include <set>
#include <unordered_map>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/HttpLayer.h>


namespace pcapfs {
    namespace ja4 {
        const std::unordered_map<uint16_t, std::string> tlsVersionMap = {
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

        std::string const calculateJa4(const pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint& fingerprint, const std::string &sni,
                                        pcpp::SSLExtension* alpn, pcpp::SSLExtension* signatureAlgorithms, pcpp::SSLExtension* supportedVersions);

        std::string const calculateJa4S(const pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint& fingerprint, pcpp::SSLExtension* alpn,
                                        pcpp::SSLExtension* supportedVersions);

        std::string const extractTlsVersion(pcpp::SSLExtension* supportedVersions, uint16_t tlsVersion);
        std::string const extractAlpn(pcpp::SSLExtension* alpn);
        std::string const getAsCommaSeparatedString(const std::vector<uint16_t> &values);
        std::string const getAsHashOfCommaSeparatedString(const std::vector<uint16_t> &values);
        std::string const getAsHashPart(const std::string &input);
        std::string const toLowerCase(const std::string &input);

        std::string const calculateJa4X(const Bytes &rawCertData);
        std::string const calculateJa4H(const pcpp::HttpRequestLayer& requestLayer, const std::string& requestMethod);
    }
}

#endif //PCAPFS_JA4_H
