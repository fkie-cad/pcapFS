#ifndef PCAPFS_VIRTUAL_FILES_UDP_H
#define PCAPFS_VIRTUAL_FILES_UDP_H

#include <boost/filesystem.hpp>

#include "../file.h"
#include "../index.h"
#include "virtualfile.h"


namespace pcapfs {

    class UdpFile : public VirtualFile {

    public:
        static FilePtr create() { return std::make_shared<UdpFile>(); };

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        static std::vector<pcapfs::FilePtr>
        createUDPVirtualFilesFromPcaps(const std::vector<pcapfs::FilePtr> &pcapFiles);

    private:
        static bool registeredAtFactory;
    };

}

#endif //PCAPFS_VIRTUAL_FILES_HTTP_H
