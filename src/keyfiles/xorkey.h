#ifndef PCAPFS_KEY_FILES_XORKEY_H
#define PCAPFS_KEY_FILES_XORKEY_H

#include <boost/filesystem.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>

#include "../commontypes.h"
#include "../file.h"


namespace pcapfs {

    class XORKeyFile : public File {
    public:
        XORKeyFile() = default;

        ~XORKeyFile() override = default;

        static FilePtr create() { return std::make_shared<XORKeyFile>(); };

        static std::vector<FilePtr> parseCandidates(const Paths &keyFiles);

        Bytes getXORKey() { return XORKey; };

        size_t read(uint64_t, size_t, const Index &, char *) override { return 0; };

        bool showFile() override { return false; };

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        static bool registeredAtFactory;

    private:
        Bytes XORKey;
    };

}

#endif //PCAPFS_KEY_FILES_XORKEY_H
