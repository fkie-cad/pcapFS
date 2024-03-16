#ifndef PCAPFS_VIRTUAL_FILES_TLS_H
#define PCAPFS_VIRTUAL_FILES_TLS_H

#include <iostream>
#include <string>
#include <vector>
#include <set>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <pcapplusplus/SSLLayer.h>

#include "../file.h"
#include "../keyfiles/tlskey.h"
#include "virtualfile.h"
#include "../crypto/ciphertextelement.h"
#include "../crypto/handshakedata.h"

namespace pcapfs {

    class TlsFile : public VirtualFile {
    public:

        static FilePtr create() { return std::make_shared<TlsFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        void serialize(boost::archive::text_oarchive &archive) override;
        void deserialize(boost::archive::text_iarchive &archive) override;

        uint64_t getKeyIDinIndex() { return keyIDinIndex; };
        std::string const getCipherSuite() { return cipherSuite; };
        uint16_t getTlsVersion() { return tlsVersion; };

        void setKeyIDinIndex(uint64_t keyIDinIndex) { this->keyIDinIndex = keyIDinIndex; };
        void setCipherSuite(const std::string &cipherSuite) { this->cipherSuite = cipherSuite; };
        void setTlsVersion(uint16_t tlsVersion) { this->tlsVersion = tlsVersion; };

        bool encryptThenMacEnabled;
        bool truncatedHmacEnabled;

    private:
        std::string const toString();

        size_t readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readDecryptedContent(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        size_t readCertificate(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        size_t getFullCipherText(const Index &idx, std::vector<CiphertextPtr> &outputCipherTextVector);

        void decryptCiphertextVecToPlaintextVec(
            const std::vector<std::shared_ptr<CipherTextElement>> &cipherTextVector,
            std::vector<Bytes> &outputPlainTextVector);

        size_t calculateProcessedSize(const Index& idx);
        size_t calculateProcessedCertSize(const Index &idx);

        static void processTLSHandshake(pcpp::SSLLayer *sslLayer, TLSHandshakeDataPtr &handshakeData, uint64_t &offset,
                                        const FilePtr &fileptr, const Index &idx);

        static void createCertFiles(const FilePtr &filePtr, uint64_t offset, const pcpp::SSLCertificateMessage* certificateMessage,
                                                        const TLSHandshakeDataPtr &handshakeData, const Index &idx);

        static void initResultPtr(const std::shared_ptr<TlsFile> &resultPtr, const FilePtr &filePtr,
                            const TLSHandshakeDataPtr &handshakeData, Index &idx);

        static bool isClientMessage(uint64_t i);

    	static bool isTLSTraffic(const FilePtr &filePtr, const Bytes &data);

        static bool isSupportedCipherSuite(const pcpp::SSLCipherSuite* cipherSuite);

        int decryptData(const CiphertextPtr &input, Bytes &output);

        static Bytes const searchCorrectMasterSecret(const TLSHandshakeDataPtr &handshakeData, const Index &idx);

    protected:
        std::string cipherSuite;
        uint16_t tlsVersion;
        static bool registeredAtFactory;
        uint64_t keyIDinIndex;
        std::vector<uint64_t> previousBytes;
        std::vector<uint64_t> keyForFragment;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_TLS_H
