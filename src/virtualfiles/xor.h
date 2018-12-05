#ifndef PCAPFS_VIRTUAL_FILES_XOR_H
#define PCAPFS_VIRTUAL_FILES_XOR_H

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include "../file.h"
#include "virtualfile.h"


namespace pcapfs {

    class XorFile : public VirtualFile {
    public:
        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        static FilePtr create() { return std::make_shared<XorFile>(); };

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void XOR(Bytes &data, char *key, size_t keySize);

    private:
        static bool registeredAtFactory;
        uint64_t keyIdInIndex;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_XOR_H
