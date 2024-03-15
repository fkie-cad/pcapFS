#include "smb_utils.h"
#include "../../exceptions.h"

#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>


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


uint16_t pcapfs::smb::strToUint16(const std::string& str) {
    char* end;
    long val = strtol(str.c_str(), &end, 10);
    if (end == str || *end != '\0' || val < 0 || val >= 0x10000)
        return 0;
    return (uint16_t) val;
}


pcapfs::TimePoint pcapfs::smb::winFiletimeToTimePoint(uint64_t winFiletime) {
    const auto unixSeconds = winFiletime == 0 ?  std::chrono::seconds{0} :
            std::chrono::seconds{(winFiletime / 10000000ULL) - 11644473600ULL};
    return TimePoint(unixSeconds);
}


std::string const pcapfs::smb::sanitizeFilename(const std::string &inFilename) {
    // chop off ending backslash(es)
    const auto it1 = std::find_if(inFilename.rbegin(), inFilename.rend(), [](const unsigned char c){ return c != 0x5C; });
    std::string temp(inFilename.begin(), it1.base());
    // chop off leading backslash(es)
    const auto it2 = std::find_if(temp.begin(), temp.end(), [](const unsigned char c){ return c != 0x5C; });
    return std::string(it2, temp.end());
}
