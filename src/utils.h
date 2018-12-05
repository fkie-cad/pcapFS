#ifndef PCAPFS_UTILS_H
#define PCAPFS_UTILS_H

#include <string>

#include <sys/time.h>

#include "commontypes.h"


namespace pcapfs {
    namespace utils {

        Paths getFilesFromPath(const Path &path, const std::string &suffix);

        Bytes hexStringToBytes(const std::string &str);

        TimePoint convertTimeValToTimePoint(const timeval &tv);
    }
}

#endif //PCAPFS_UTILS_H
