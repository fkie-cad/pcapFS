#ifndef PCAPFS_SMB_UTILS_H
#define PCAPFS_SMB_UTILS_H

#include "../../file.h"
#include "../../commontypes.h"

namespace pcapfs {
    namespace smb {
        size_t calculate311NegotiateMessageLength(const Bytes &rawData, uint32_t negotiateContextOffset,
                                                    uint16_t negotiateContextCount);
        std::string const wstrToStr(const Bytes &input);
        std::string const bytesToHexString(const Bytes &input);
        uint16_t strToUint16(const std::string& str);
        TimePoint winFiletimeToTimePoint(uint64_t winFiletime);
    }
}

#endif //PCAPFS_SMB_UTILS_H
