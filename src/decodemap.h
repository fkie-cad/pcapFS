#ifndef PCAPFS_DECODEMAP_H
#define PCAPFS_DECODEMAP_H

#include <unordered_map>
#include <string>
#include <vector>


namespace pcapfs {

    typedef std::unordered_map<std::string, std::string> DecodeCriterion;
    typedef std::vector<DecodeCriterion> DecodeMapEntry;
    typedef std::unordered_map<std::string, DecodeMapEntry> DecodeMap;

}

#endif //PCAPFS_DECODEMAP_H
