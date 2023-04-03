#ifndef PCAPFS_COBALTSTRIKE_H
#define PCAPFS_COBALTSTRIKE_H

#include <set>
#include <unordered_map>
#include "commontypes.h"

namespace pcapfs {

    typedef struct CobaltStrikeConnection {
        std::string serverIp;
        std::string serverPort;
        Bytes aesKey;
        Bytes hmacKey;

        std::pair<std::string,std::string> identifier() {
            return std::make_pair(serverIp, serverPort);
        }
    } CobaltStrikeConnection;

    typedef std::shared_ptr<CobaltStrikeConnection> CobaltStrikeConnectionPtr;
    
    class CobaltStrike {
    public:
        static CobaltStrike& getInstance() {
            static CobaltStrike instance;
            return instance;
        }

        CobaltStrike(CobaltStrike const&) = delete;
        void operator=(CobaltStrike const&) = delete;

        void handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort);
        bool isKnownConnection(const std::string &ServerIp, const std::string &ServerPort);
        Bytes const decryptPayload(const Bytes& input, const std::string &serverIp, const std::string &serverPort);
        CobaltStrikeConnectionPtr getConnectionData(const std::string &serverIp, const std::string &serverPort);

    private:
        CobaltStrike() {}

        bool matchMagicBytes(const Bytes& input);
        void addConnectionData(const Bytes& rawKey, const std::string &dstIp, const std::string &dstPort);
        int opensslDecryptCS(const Bytes &dataToDecrypt, const Bytes &aesKey, Bytes &decryptedData);

        std::vector<CobaltStrikeConnectionPtr> connections;
        //std::vector<std::string> knownCookies;

        const std::set<std::string> privKeyCandidates = {
                            "-----BEGIN RSA PRIVATE KEY-----\n" \
                            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKc4zedfH7scGGRs\n" \
                            "N34DAWsWKxK6cr333Da0zS5Om64SIFqVwmFwv5CBBa1/pLvM+nmGMiYb7Zhw+XXy\n" \
                            "B5Th/kmVI9cfCKVsrgMVv949bIoWOGsDt6ZVGqEzbVAyWjUA2yfXitj9E7anO5+3\n" \
                            "w/tNegiOMj8HYYZW7Ng1lfpfgjYTAgMBAAECgYBZ63DFTuB4NBZlwc9hQmp71BLb\n" \
                            "YkkbH/JZtIV0ti5+vx6It2ksDn3kTYzpC+9gUUwLFv9WgMQVqgJqyvgKti+PMGmM\n" \
                            "cTJTDd1GpEt3dzhwNzEuScWdxaAOIJZ0NfdMrGcDogHsNDG4YAjg2XP6d1eZvHuI\n" \
                            "YwNycKM4KcCB5suqEQJBAOJdR3jg0eHly2W+ODb11krwbQVOxuOwP3j2veie8tnk\n" \
                            "uTK3NfwmSlx6PSp8ZtABh8PcpRw+91j9/ecFZMHC6OkCQQC9HVV20OhWnXEdWspC\n" \
                            "/YCMH3CFxc7SFRgDYK2r1sVTQU/fTM2bkdaZXDWIZjbLFOb0U7/zQfVsuuZyGMFw\n" \
                            "dwmbAkBiDxJ1FL8W4pr32i0z8c8A66HumK+j1qfIWOrvqFt/dIudoqwqLNQtt25j\n" \
                            "xzwqg18yw5Rq5gP0cyLYPwfkv/BxAkAtLhnh5ezr7Hc+pRcXRAr27vfp7aUIiaOQ\n" \
                            "AwPavtermTnkxiuE1CWpw97CNHE4uUin7G46RnLExC4T6hgkrzurAkEAvRVFgcXT\n" \
                            "mcg49Ha3VIKIb83xlNhBnWVkqNyLnAdOBENZUZ479oaPw7Sl+N0SD15TgT25+4P6\n" \
                            "PKH8QE6hwC/g5Q==\n" \
                            "-----END RSA PRIVATE KEY-----\n"
                            };
    };
}

#endif // PCAPFS_COBALTSTRIKE_H
