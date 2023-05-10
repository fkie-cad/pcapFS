#include "cs_manager.h"

#include <boost/beast/core/detail/base64.hpp>
#include "../crypto/cryptutils.h"
#include "../keyfiles/cskey.h"


void pcapfs::CobaltStrikeManager::handleHttpGet(const std::string &cookie, const std::string &dstIp, const std::string &dstPort,
                                                const std::string &srcIp, const pcapfs::Index &idx) {

    if (isKnownConnection(dstIp, dstPort, srcIp) || cookie.length() <= 34)
        // when the cookie is shorter than 34 characters, the raw key can't be encoded in it
        return;

    LOG_TRACE << "HTTP Header Cookie: " << cookie;
    LOG_TRACE << "check if cookie belongs to cobalt strike";

    Bytes toDecrypt(3*(cookie.length()/4) - 1); // TODO: change size of toDecrypt?
    boost::beast::detail::base64::decode(toDecrypt.data(), cookie.c_str(), cookie.length());

    Bytes result(toDecrypt.size());
    std::vector<pcapfs::FilePtr> keyFiles = idx.getCandidatesOfType("cskey");
    for (auto &keyFile: keyFiles) {
        std::shared_ptr<CSKeyFile> csKeyFile = std::dynamic_pointer_cast<CSKeyFile>(keyFile);
        if (!csKeyFile) {
            LOG_ERROR << "dynamic_pointer_cast failed for cs key file";
            continue;
        }
        const Bytes privKey = csKeyFile->getRsaPrivateKey();
        result = crypto::rsaPrivateDecrypt(toDecrypt, privKey, false);
        if (!result.empty()) {

            if (matchMagicBytes(result)) {
                LOG_INFO << "found cobalt strike communication";
                // extract symmetric key material
                Bytes rawKey(result.begin()+8, result.begin()+8+16);
                addConnectionData(rawKey, dstIp, dstPort, srcIp);
            }
        }
    }
}


bool pcapfs::CobaltStrikeManager::isKnownConnection(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp) {
    return std::any_of(connections.begin(), connections.end(),
                        [serverIp,serverPort,clientIp](const CobaltStrikeConnectionPtr &conn){
                            return (conn->serverIp == serverIp && conn->serverPort == serverPort && conn->clientIp == clientIp); });
}


bool pcapfs::CobaltStrikeManager::matchMagicBytes(const Bytes& input) {
    const Bytes magicBytes = {0x00, 0x00, 0xbe, 0xef};
    for (int i = 0; i < 4; ++i) {
        if (input[i] != magicBytes [i])
            return false;
    }
    return true;
}


void pcapfs::CobaltStrikeManager::addConnectionData(const Bytes &rawKey, const std::string &dstIp, const std::string &dstPort, const std::string &srcIp) {
    Bytes digest = crypto::calculateSha256(rawKey);
    if (digest.empty())
        return;

    CobaltStrikeConnectionPtr newConnection = std::make_shared<CobaltStrikeConnection>();
    newConnection->aesKey = Bytes(digest.begin(), digest.begin()+16);
    //newConnection->hmacKey = Bytes(digest.begin()+16, digest.end());
    newConnection->serverIp = dstIp;
    newConnection->serverPort = dstPort;
    newConnection->clientIp = srcIp;
    connections.push_back(newConnection);
}


pcapfs::CobaltStrikeConnectionPtr pcapfs::CobaltStrikeManager::getConnectionData(const std::string &serverIp, const std::string &serverPort, const std::string &clientIp) {
    CobaltStrikeConnectionPtr result;
    auto it = std::find_if(connections.cbegin(), connections.cend(),
                         [serverIp,serverPort,clientIp](const CobaltStrikeConnectionPtr &conn){
                            return (conn->serverIp == serverIp && conn->serverPort == serverPort && conn->clientIp == clientIp); });
    if (it != connections.cend())
        result = *it;
    return result;
}
