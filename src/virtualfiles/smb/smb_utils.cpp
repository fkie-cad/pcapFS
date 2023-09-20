#include "smb_utils.h"
#include "../../exceptions.h"


size_t pcapfs::smb::calculate311NegotiateMessageLength(const Bytes &rawData, uint32_t negotiateContextOffset,
                                                        uint16_t negotiateContextCount) {
    size_t currPos = negotiateContextOffset - 64;
    for (size_t i = 0; i < negotiateContextCount; ++i) {
        uint16_t dataLength = (*(uint16_t*) &rawData.at(currPos + 2)) + 8;
        if (dataLength > rawData.size() - currPos)
            throw PcapFsException("Invalid negotiate context values in SMB Negotiate Message");
        currPos += dataLength;
    }
    return currPos;
}
