#ifndef PCAPFS_CS_MANAGER_H
#define PCAPFS_CS_MANAGER_H

#include <set>
#include "../commontypes.h"
#include "../index.h"

namespace pcapfs {

    typedef struct CobaltStrikeConnection {
        std::string serverIp;
        std::string serverPort;
        std::string clientIp;
        Bytes aesKey;

    } CobaltStrikeConnection;

    typedef std::shared_ptr<CobaltStrikeConnection> CobaltStrikeConnectionPtr;

    class CobaltStrikeManager {
    public:
        static CobaltStrikeManager& getInstance() {
            static CobaltStrikeManager instance;
            return instance;
        }

        CobaltStrikeManager(CobaltStrikeManager const&) = delete;
        void operator=(CobaltStrikeManager const&) = delete;

        void handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp, const Index &idx);
        CobaltStrikeConnectionPtr getConnectionData(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);
        bool isKnownConnection(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp);

    private:
        CobaltStrikeManager() {}

        bool matchMagicBytes(const Bytes& input);
        void addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp);

        std::vector<CobaltStrikeConnectionPtr> connections;
    };
}

#endif // PCAPFS_CS_MANAGER_H
