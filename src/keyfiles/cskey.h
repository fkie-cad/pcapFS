#ifndef PCAPFS_KEY_FILES_CSKEY_H
#define PCAPFS_KEY_FILES_CSKEY_H

#include "../commontypes.h"
#include "../file.h"

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/serialization/vector.hpp>


namespace pcapfs {

    class CSKeyFile : public File {
    public:
        CSKeyFile() = default;

        ~CSKeyFile() override = default;

        static FilePtr create() { return std::make_shared<CSKeyFile>(); };

        static std::vector<FilePtr> parseCandidates(const Paths &keyFiles);

        Bytes getRsaPrivateKey() { return rsaPrivateKey; };

        size_t read(uint64_t, size_t, const Index &, char *) override { return 0; };

        bool showFile() override { return false; };

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        static bool registeredAtFactory;

    private:
        Bytes rsaPrivateKey;
    };
}

#endif // PCAPFS_KEY_FILES_CSKEY_H
