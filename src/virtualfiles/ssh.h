#ifndef PCAPFS_VIRTUAL_FILES_SSH_H
#define PCAPFS_VIRTUAL_FILES_SSH_H

#include "virtualfile.h"
#include <pcapplusplus/SSHLayer.h>


namespace pcapfs {

    class SshFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<SshFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        static bool isSshTraffic(const FilePtr& filePtr);
        static bool isOdd(uint64_t i);
        static size_t getLenOfIdentMsg(pcpp::SSHLayer *sshLayer);
        static std::string const computeHassh(pcpp::SSHKeyExchangeInitMessage* clientKexInitMsg);
        static std::string const computeHasshServer(pcpp::SSHKeyExchangeInitMessage* serverKexInitMsg);
    protected:
        static bool registeredAtFactory;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SSH_H
