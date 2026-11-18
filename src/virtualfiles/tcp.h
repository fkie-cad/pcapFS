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


    protected:
        static bool registeredAtFactory;

        typedef std::shared_ptr<pcapfs::TcpFile> TCPPtr;
        // key: (connection generation << 32) | flow key of the reassembly library
        typedef std::map<uint64_t, TCPPtr> TCPStreamMap;
        typedef std::map<uint64_t, int> sideMap;

        // A 5-tuple can be used by several consecutive connections (e.g. the Linux NFS client reconnects from the
        // same reserved source port). Each such connection is one "generation" of the flow.
        static constexpr uint32_t MAX_CONNECTION_GENERATIONS = 65536;
        struct FlowGeneration {
            uint32_t generation = 0;
            bool sawNonSyn = false;
            bool sawFinOrRst = false;
            bool sawSynAck = false;
            // initial sequence numbers of the SYNs seen in this generation (two in a simultaneous open)
            uint8_t synSeqCount = 0;
            uint32_t synSeqs[2] = {0, 0};
            bool knowsSynSeq(uint32_t seq) const {
                return (synSeqCount > 0 && synSeqs[0] == seq) || (synSeqCount > 1 && synSeqs[1] == seq);
            }
        };

        class TCPContent {
        public:
            TCPContent(const TCPContent &other);
            TCPContent& operator=(const TCPContent &other);

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

        struct TCPFragment {
            Fragment fragment;
            uint64_t frameNr;
        };

        struct TCPIndexerState {
            TCPStreamMap files;
            std::unordered_map<TCPContent, std::queue<TCPFragment>, TCPContentHasher> outOfOrderPackets;
            bool gotCallback;
            TCPFragment currentFragment;
            size_t nextUniqueId = 0;
            uint64_t currentPcapFileId;
            TimePoint currentTimestamp;
            sideMap currentSide;
            bool isPcapng;
            uint32_t currentGeneration = 0;
            std::map<uint32_t, FlowGeneration> flowGenerations;
        };

        static void messageReadycallback(signed char side, const pcpp::TcpStreamData &tcpData, void *userCookie);
    };

}

#endif //PCAPFS_VIRTUAL_FILES_TCP_H
