#include "smb_utils.h"
#include "../../exceptions.h"

#include <sstream>
#include <iomanip>


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

std::string const pcapfs::smb::wstrToStr(const Bytes &input) {
    Bytes temp(input.begin(), input.end());
    temp.erase(std::remove(temp.begin(), temp.end(), (unsigned char)0x00), temp.end());
    return std::string(temp.begin(), temp.end());
}

std::string const pcapfs::smb::bytesToHexString(const Bytes &input) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < input.size(); ++i)
        ss <<  std::setw(2) << (int)input.at(i);
    return ss.str();
}