#include "utils.h"

#include <iterator>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include "exceptions.h"


namespace fs = boost::filesystem;


namespace {

    bool isFileToUse(const pcapfs::Path &path, const std::string &suffix) {
        return fs::is_regular_file(path) && (suffix.empty() || boost::algorithm::ends_with(path.string(), suffix));
    }


    pcapfs::Paths getPathsFromDirectory(const pcapfs::Path &path, const std::string &suffix) {
        pcapfs::Paths files;
        for (auto file = fs::directory_iterator(path);
             file != fs::directory_iterator(); ++file) {
            if (isFileToUse(file->path(), suffix)) {
                files.emplace_back(file->path().string());
            }
        }
        sort(files.begin(), files.end());
        return files;
    }
}


pcapfs::Paths pcapfs::utils::getFilesFromPath(const pcapfs::Path &path, const std::string &suffix) {
    if (!fs::exists(path)) {
        throw pcapfs::ArgumentError("Path '" + path.string() + "' does not exists.");
    }
    Paths files;
    if (fs::is_regular_file(path)) {
        files.emplace_back(path);
    } else if (fs::is_directory(path)) {
        files = getPathsFromDirectory(path, suffix);
    } else {
        throw pcapfs::PcapFsException("Path '" + path.string() + "' is neither a directory nor a regular file.");
    }
    return files;
}


pcapfs::Bytes pcapfs::utils::hexStringToBytes(const std::string &str) {
    Bytes data;
    boost::algorithm::unhex(str.c_str(), std::back_inserter(data));
    return data;
}


pcapfs::TimePoint pcapfs::utils::convertTimeValToTimePoint(const timespec &tv) {
    const auto d = std::chrono::seconds{tv.tv_sec} + std::chrono::nanoseconds{tv.tv_nsec};
    return TimePoint(d);
}
