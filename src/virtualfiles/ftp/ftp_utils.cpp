#include "ftp_utils.h"
#include "../../exceptions.h"

#include <boost/algorithm/string.hpp>


pcapfs::FtpFileMetaData const pcapfs::ftp::parseMetadataLine(std::string &line) {
    size_t spacePos = line.rfind("; ");
    if (spacePos == std::string::npos || spacePos + 3 >= line.length())
        throw PcapFsException("FTP: invalid metadata line");

    // -1 because of ending newline
    const std::string extractedFilename(line.begin()+spacePos+2, line.end()-1);
    if (extractedFilename.empty() || std::any_of(extractedFilename.begin(), extractedFilename.end(), [](char c) { return !std::isprint(c); }))
        throw PcapFsException("FTP: invalid metadata line");

    FtpFileMetaData result;
    result.filename = extractedFilename;

    std::stringstream ss(line);
    std::string token;
    while(std::getline(ss, token, ';')) {
        std::stringstream ss2(token);
        std::string key, value;
        if (std::getline(ss2, key, '=') && std::getline(ss2, value)) {
            if (boost::iequals(key, "modify") && !value.empty()) {
                std::tm tm = {};
                std::stringstream ss3(value);
                ss3 >> std::get_time(&tm, "%Y%m%d%H%M%S");
                result.modifyTime = std::chrono::system_clock::from_time_t(std::mktime(&tm));
            } else if (boost::iequals(key, "type")) {
                result.isDir = boost::iequals(value, "dir");
            }
        }
    }

    return result;
}