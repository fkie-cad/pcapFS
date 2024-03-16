#ifndef PCAPFS_KEY_FILES_TLSKEY_H
#define PCAPFS_KEY_FILES_TLSKEY_H

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/filesystem.hpp>
#include <boost/serialization/vector.hpp>

#include "../commontypes.h"
#include "../file.h"


namespace pcapfs {

    class TLSKeyFile : public File {
    public:
        TLSKeyFile() = default;

        ~TLSKeyFile() override = default;

        static FilePtr create() { return std::make_shared<TLSKeyFile>(); };

        static std::vector<FilePtr> parseCandidates(const Paths &keyFiles);

        static std::shared_ptr<TLSKeyFile> extractKeyContent(const std::string &line);

        static std::shared_ptr<pcapfs::TLSKeyFile> createKeyFile(const Bytes &keyMaterial);

        Bytes getMasterSecret() { return masterSecret; };

        Bytes getPreMasterSecret() { return preMasterSecret; };

        Bytes getRsaIdentifier() { return rsaIdentifier; };

        Bytes getClientRandom() { return clientRandom; };

        Bytes getKeyMaterial() { return keyMaterial; };

        Bytes getRsaPrivateKey() { return rsaPrivateKey; };

        size_t read(uint64_t, size_t, const Index &, char *) override { return 0; };

        bool showFile() override { return false; };

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

        static bool registeredAtFactory;

    private:
        Bytes clientRandom;
        Bytes masterSecret;
        Bytes rsaIdentifier;
        Bytes preMasterSecret;
        Bytes keyMaterial;
        Bytes rsaPrivateKey;

    };

}

#endif //PCAPFS_KEY_FILES_TLSKEY_H
