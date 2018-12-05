#ifndef PCAPFS_OFFSETS_H
#define PCAPFS_OFFSETS_H

#include <cstdint>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>


struct SimpleOffset {
    uint64_t id;
    uint64_t start;
    uint64_t length;

    template<class Archive>
    void serialize(Archive &archive, const unsigned int) {
        archive & id;
        archive & start;
        archive & length;
    }
};

#endif //PCAPFS_OFFSETS_H
