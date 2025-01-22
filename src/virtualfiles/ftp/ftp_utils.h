#ifndef PCAPFS_FTP_UTILS_H
#define PCAPFS_FTP_UTILS_H

#include "../../commontypes.h"
#include "../virtualfile.h"

namespace pcapfs {

    struct FtpFileMetaData {
        std::string filename;
        TimePoint modifyTime = ZERO_TIME_POINT;
        bool isDir = false;
    };

    struct FtpResponse {
        uint16_t code;
        std::string message;
        TimePoint timestamp;
    };

    namespace ftp {
        FtpFileMetaData const parseMetadataLine(std::string &line);
    }
}

#endif //PCAPFS_FTP_UTILS_H
