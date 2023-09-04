#ifndef PCAPFS_VIRTUAL_FILES_DNS_H
#define PCAPFS_VIRTUAL_FILES_DNS_H

#include <string>
#include <pcapplusplus/DnsLayer.h>
#include <nlohmann/json.hpp>

#include "virtualfile.h"


namespace pcapfs {

    class DnsFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<DnsFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        std::string const dnsClassToString(const pcpp::DnsClass dnsClass);
        std::string const dnsTypeToString(pcpp::DnsType type);
        std::vector<nlohmann::json> const parseDnsAnswersToJson(const pcpp::DnsLayer &dnsLayer);
        std::string const parseDnsToJson(pcapfs::Bytes data);

        std::string const getDataAsString(pcpp::DnsResource *resource);

        size_t calculateProcessedSize(const Index &idx);

    protected:
        static bool registeredAtFactory;
    };

}

#endif //PCAPFS_VIRTUAL_FILES_DNS_H
