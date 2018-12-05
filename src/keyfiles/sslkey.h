#ifndef PCAPFS_KEY_FILES_SSLKEY_H
#define PCAPFS_KEY_FILES_SSLKEY_H

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/serialization/vector.hpp>

#include "../commontypes.h"
#include "../file.h"


namespace pcapfs {

    class SSLKeyFile : public File {
    public:
        SSLKeyFile() = default;

        ~SSLKeyFile() override = default;

        static FilePtr create() { return std::make_shared<SSLKeyFile>(); };

        static std::vector<FilePtr> parseCandidates(const Paths &keyFiles);

        static std::shared_ptr<pcapfs::SSLKeyFile> createKeyFile(Bytes &keyMaterial);

        //TODO: remove key and mac size from arguments?
        Bytes getClientWriteKey(uint64_t keySize, uint64_t macSize);

        Bytes getServerWriteKey(uint64_t keySize, uint64_t macSize);

        Bytes getMasterSecret() { return masterSecret; };

        Bytes getClientRandom() { return clientRandom; };

        size_t read(uint64_t, size_t, const Index &, char *) override { return 0; };

        bool showFile() override { return false; };

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        static bool registeredAtFactory;

    private:
        Bytes clientRandom;
        Bytes masterSecret;
        Bytes keyMaterial;

    };

}

#endif //PCAPFS_KEY_FILES_SSLKEY_H
