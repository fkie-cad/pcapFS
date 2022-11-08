#ifndef PCAPFS_OFFSETS_H
#define PCAPFS_OFFSETS_H

#include <cstdint>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


struct Fragment {
    uint64_t id = 0L;
    uint64_t start = 0L;
    uint64_t length = 0L;

    template<class Archive>
    void serialize(Archive &archive, const unsigned int) {
        archive & id;
        archive & start;
        archive & length;
    }
};

#endif //PCAPFS_OFFSETS_H
