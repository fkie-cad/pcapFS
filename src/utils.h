#ifndef PCAPFS_UTILS_H
#define PCAPFS_UTILS_H

#include <ctime>
#include <string>

#include "commontypes.h"


namespace pcapfs {
    namespace utils {

        Paths getFilesFromPath(const Path &path, const std::string &suffix);

        Bytes hexStringToBytes(const std::string &str);

        TimePoint convertTimeValToTimePoint(const timespec &tv);
    }
}

#endif //PCAPFS_UTILS_H
