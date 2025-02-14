#ifndef PCAPFS_PROPERTIES_H
#define PCAPFS_PROPERTIES_H

#include <string>

namespace pcapfs {
    struct prop {
        static const std::string protocol;
        static const std::string dstPort;
        static const std::string srcPort;
        static const std::string dstIP;
        static const std::string srcIP;
        static const std::string uri;
        static const std::string domain;
        static const std::string ja3;
        static const std::string ja3s;
        static const std::string ja4;
        static const std::string ja4s;
        static const std::string ja4x;
        static const std::string ja4h;
        static const std::string hassh;
        static const std::string hasshServer;
    };
}

#endif //PCAPFS_PROPERTIES_H
