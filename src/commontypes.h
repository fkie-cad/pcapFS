#ifndef PCAPFS_COMMON_TYPES_H
#define PCAPFS_COMMON_TYPES_H

#include <chrono>
#include <cstdint>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/binary_object.hpp>

#include "commontypes.h"


namespace pcapfs {

    typedef unsigned char Byte;
    typedef std::vector<Byte> Bytes;

    typedef boost::filesystem::path Path;
    typedef std::vector<Path> Paths;

    using TimePoint = std::chrono::system_clock::time_point;
    using TimeSlot = std::pair<TimePoint, TimePoint>;

    const TimePoint ZERO_TIME_POINT{};
}

/*
    Serialization function for TimePoint
*/
namespace boost {
    namespace serialization {
        template<class Archive>
        void serialize(Archive &archive, pcapfs::TimePoint &timePoint, const unsigned int) {
            archive & make_binary_object(&timePoint, sizeof(timePoint));
        };
    }
}

#endif //PCAPFS_COMMON_TYPES_H
