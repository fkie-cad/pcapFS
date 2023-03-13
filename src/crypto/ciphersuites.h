#ifndef PCAPFS_CRYPTO_CIPHERSUITES_H
#define PCAPFS_CRYPTO_CIPHERSUITES_H

#include <set>
#include <cstdint>

namespace pcapfs {
    namespace crypto {
        const std::set<uint16_t> supportedCipherSuiteIds = {
            0x0004, // TLS_RSA_WITH_RC4_128_MD5
            0x0005, // TLS_RSA_WITH_RC4_128_SHA
            0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
            0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x0034, // TLS_DH_anon_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x003A, // TLS_DH_anon_WITH_AES_256_CBC_SHA
            0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
            0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
            0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
            0x006C, // TLS_DH_anon_WITH_AES_128_CBC_SHA256
            0x006D, // TLS_DH_anon_WITH_AES_256_CBC_SHA256
            0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
            0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
            0x00A6, // TLS_DH_anon_WITH_AES_128_GCM_SHA256
            0x00A7, // TLS_DH_anon_WITH_AES_256_GCM_SHA384
            0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
            0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0xC016, // TLS_ECDH_anon_WITH_RC4_128_SHA
            0xC018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
            0xC019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
            0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        };
    }
}

#endif //PCAPFS_CRYPTO_CIPHERSUITES_H