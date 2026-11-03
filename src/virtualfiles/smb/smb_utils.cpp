#include "smb_utils.h"
#include "smb_constants.h"
#include "../../exceptions.h"
#include "../../properties.h"

#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>


bool pcapfs::smb::isSmbOverTcp(const FilePtr &filePtr, const Bytes &data, bool checkNonDefaultPorts) {
    if (filePtr->getProperty(prop::protocol) == "tcp" &&
        data.size() > 68 && data.at(0) == 0x00 && be32toh(*(uint32_t*) &data.at(0)) != 0 &&
        (memcmp(&data.at(4), smb::SMB2_MAGIC, 4) == 0 || memcmp(&data.at(4), smb::SMB1_MAGIC, 4) == 0) &&
        (checkNonDefaultPorts || (filePtr->getProperty(prop::srcPort) == "445" || filePtr->getProperty(prop::dstPort) == "445")))
        return true;
    else
        return false;
}


size_t pcapfs::smb::getSmbOffsetAfterNbssSetup(const FilePtr &filePtr, const Bytes &data, bool checkNonDefaultPorts) {
    // returns offset where smb Traffic begins after Netbios Session Setup
    if (filePtr->getProperty(prop::protocol) == "tcp" && data.size() > 68 && (checkNonDefaultPorts ||
        (filePtr->getProperty(prop::srcPort) == "139" || filePtr->getProperty(prop::dstPort) == "139"))) {
        for (size_t pos = 0; pos < data.size() - 8; ++pos) {
            if (data.at(pos) == 0x00 && be32toh(*(uint32_t*) &data.at(pos)) != 0 &&
                (memcmp(&data.at(pos+4), smb::SMB2_MAGIC, 4) == 0 || memcmp(&data.at(pos+4), smb::SMB1_MAGIC, 4) == 0))
                return pos;
        }
    }
    return (size_t)-1;
}


size_t pcapfs::smb::calculate311NegotiateMessageLength(const Bytes &rawData, uint32_t negotiateContextOffset,
                                                        uint16_t negotiateContextCount) {
    size_t currPos = negotiateContextOffset - 64;
    for (size_t i = 0; i < negotiateContextCount; ++i) {
        if (currPos + 8 > rawData.size())
            throw SmbError("Invalid negotiate context values in SMB Negotiate Message");
        uint16_t entryDataLen;
        std::memcpy(&entryDataLen, &rawData.at(currPos + 2), sizeof(entryDataLen));
        const size_t tmpLen = static_cast<size_t>(entryDataLen) + 8;
        if (i == static_cast<size_t>(negotiateContextCount - 1)) {
            // no 8-byte alignment for last context entry
            if (tmpLen > rawData.size() - currPos)
                throw SmbError("Invalid negotiate context values in SMB Negotiate Message");
            currPos += tmpLen;
        } else {
            const size_t aligned = (tmpLen + 7u) & ~static_cast<size_t>(7u);
            if (aligned > rawData.size() - currPos)
                throw SmbError("Invalid negotiate context values in SMB Negotiate Message");
            currPos += aligned;
        }
    }
    return currPos;
}


static void appendUtf8(std::string &out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        // U+FFFD REPLACEMENT CHARACTER
        out.append("\xEF\xBF\xBD");
    }
}


std::string const pcapfs::smb::wstrToStr(const uint8_t* data, size_t len) {
    // SMB strings are UTF-16LE per MS-SMB2; convert to UTF-8.
    std::string result;
    result.reserve(len);
    const size_t units = len / 2;
    for (size_t i = 0; i < units; ++i) {
        uint16_t hi = static_cast<uint16_t>(data[2 * i]) |
                      (static_cast<uint16_t>(data[2 * i + 1]) << 8);
        uint32_t cp;
        if (hi >= 0xD800 && hi <= 0xDBFF) {
            // high surrogate, look for matching low surrogate
            if (i + 1 < units) {
                uint16_t lo = static_cast<uint16_t>(data[2 * (i + 1)]) |
                              (static_cast<uint16_t>(data[2 * (i + 1) + 1]) << 8);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((static_cast<uint32_t>(hi - 0xD800) << 10) | (lo - 0xDC00));
                    ++i;
                } else {
                    cp = 0xFFFD;
                }
            } else {
                cp = 0xFFFD;
            }
        } else if (hi >= 0xDC00 && hi <= 0xDFFF) {
            // stray low surrogate
            cp = 0xFFFD;
        } else {
            cp = hi;
        }
        appendUtf8(result, cp);
    }
    return result;
}


std::string const pcapfs::smb::wstrToStr(const Bytes &input) {
    return wstrToStr(input.data(), input.size());
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


std::string const pcapfs::smb::determineClientIP(const FilePtr &filePtr) {
    const uint16_t srcPort = strToUint16(filePtr->getProperty(prop::srcPort));
    return srcPort == 445 || srcPort == 139 ? filePtr->getProperty(prop::dstIP) : filePtr->getProperty(prop::srcIP);
}
