#ifndef PCAPFS_COMMON_TYPES_H
#define PCAPFS_COMMON_TYPES_H

#include <chrono>
#include <cstdint>
#include <vector>

#include <boost/filesystem.hpp>

#include "commontypes.h"


namespace pcapfs {

    typedef unsigned char Byte;
    typedef std::vector<Byte> Bytes;

    typedef boost::filesystem::path Path;
    typedef std::vector<Path> Paths;

    using TimePoint = std::chrono::system_clock::time_point;
    using TimeSlot = std::pair<TimePoint, TimePoint>;
}

#endif //PCAPFS_COMMON_TYPES_H
