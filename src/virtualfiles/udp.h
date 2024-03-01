#ifndef PCAPFS_VIRTUAL_FILES_UDP_H
#define PCAPFS_VIRTUAL_FILES_UDP_H

#include "../file.h"
#include "../index.h"
#include "virtualfile.h"

#include <chrono>
#include <boost/filesystem.hpp>
#include <pcapplusplus/Packet.h>


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


    struct UdpEndpoint {
        std::string ipAddress;
        uint16_t port = 0;

        bool operator==(const UdpEndpoint &endp) const {
            return endp.ipAddress == ipAddress && endp.port == port;
        };

    };


    class UdpConnection {
    public:
        UdpConnection(const pcpp::Packet &packet, const TimePoint &timestamp);
        bool operator==(const UdpConnection &conn) const {
            return ((conn.endpoint1 == endpoint1 && conn.endpoint2 == endpoint2) ||
                    (conn.endpoint1 == endpoint2 && conn.endpoint2 == endpoint1)) &&
                    // new UDP "connection" after 30 seconds
                    std::chrono::duration_cast<std::chrono::seconds>(conn.startTime - startTime).count() < 30;
        };

        bool operator<(const UdpConnection &conn) const {
            return startTime < conn.startTime;
        };

        bool directionChanged (const UdpConnection &conn);

        UdpEndpoint endpoint1;
        UdpEndpoint endpoint2;
        TimePoint startTime;
        mutable bool streamsToEndpoint1 = false;
    };


    struct UdpIndexerState {
        std::map<UdpConnection, std::shared_ptr<pcapfs::UdpFile>> files;
        Fragment currentOffset;
        size_t nextUniqueId = 0;
        uint64_t currentPcapfileID;
        pcapfs::TimePoint currentTimestamp;
    };

}

#endif //PCAPFS_VIRTUAL_FILES_HTTP_H
