#ifndef PCAPFS_VIRTUAL_FILES_DNS_H
#define PCAPFS_VIRTUAL_FILES_DNS_H

#include <string>

#include <pcapplusplus/DnsLayer.h>

#include "virtualfile.h"


namespace pcapfs {

    class DnsFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<DnsFile>(); };

        //TODO: make this virtual in superclass?
        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        size_t calculateProcessedSize(const Index &idx);

        static std::string getDataAsString(pcpp::DnsResource *resource);

    protected:
        static bool registeredAtFactory;
    };

}

#endif //PCAPFS_VIRTUAL_FILES_DNS_H
