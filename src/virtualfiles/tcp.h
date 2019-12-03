#ifndef PCAPFS_VIRTUAL_FILES_TCP_H
#define PCAPFS_VIRTUAL_FILES_TCP_H

#include <chrono>
#include <queue>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpReassembly.h>

#include "../filefactory.h"
#include "virtualfile.h"
#include "../commontypes.h"


namespace pcapfs {

    class TcpFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<TcpFile>(); };

        std::vector<pcapfs::FilePtr>
        static createVirtualFilesFromPcaps(const std::vector<pcapfs::FilePtr> &pcapFiles);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        //methods and classes used for tcp reassembly
        static int calcIpPayload(pcpp::Packet &p);

    protected:
        static bool registeredAtFactory;

        typedef std::shared_ptr<pcapfs::TcpFile> TCPPtr;
        typedef std::map<uint32_t, TCPPtr> TCPStreamMap;
        typedef std::map<uint32_t, int> sideMap;

        class TCPContent {
        public:
            TCPContent(const TCPContent &other);

            TCPContent(const uint8_t *copy_from, size_t datalen);

            ~TCPContent();

            size_t datalen;
            uint8_t *data;

            bool isEqual(const uint8_t *Other, size_t other_len) const;

            inline bool operator==(const TCPContent &other) const {
                return isEqual(other.data, other.datalen);
            }
        };

        struct TCPContentHasher {
            size_t operator()(const TCPContent &t) const;
        };

        struct TCPOffset {
            SimpleOffset soff;
            uint64_t frameNr;
        };

        struct TCPIndexerState {
            TCPStreamMap files;
            std::unordered_map<TCPContent, std::queue<TCPOffset>, TCPContentHasher> outOfOrderPackets;
            bool gotCallback;
            TCPOffset currentOffset;
            size_t nextUniqueId = 0;
            uint64_t currentPcapFileId;
            TimePoint currentTimestamp;
            sideMap currentSide;
        };

        static void messageReadycallback(int side, const pcpp::TcpStreamData &tcpData, void *userCookie);
    };

}

#endif //PCAPFS_VIRTUAL_FILES_TCP_H
