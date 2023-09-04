#ifndef PCAPFS_VIRTUAL_FILES_DHCP_H
#define PCAPFS_VIRTUAL_FILES_DHCP_H

#include <string>
#include <set>
#include <pcapplusplus/DhcpLayer.h>
#include <nlohmann/json.hpp>

#include "virtualfile.h"


namespace pcapfs {

    class DhcpFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<DhcpFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        static bool isDhcpTraffic(const FilePtr &filePtr);
        size_t calculateProcessedSize(const Index &idx);
        std::string const parseDhcpToJson(Bytes data);
        nlohmann::json const parseDhcpOptions(const pcpp::DhcpLayer &dhcpLayer);
        std::string const rawBytesToString(uint8_t* data, size_t len);
        bool isInSet(const std::set<uint8_t> &set, uint8_t val);

    protected:
        static bool registeredAtFactory;
    };

    const std::vector<std::string> dhcpMessageTypes = {
        "Unknown",
        "DHCP Discover",
        "DHCP Offer",
        "DHCP Request",
        "DHCP Decline",
        "DHCP ACK",
        "DHCP NAK",
        "DHCP Release",
        "DHCP Inform",
        "Unknown",
        "DHCP Lease Query",
        "DHCP Lease Unassigned",
        "DHCP Lease Unknown",
        "DHCP Lease Active",

    };
}

#endif //PCAPFS_VIRTUAL_FILES_DHCP_H
