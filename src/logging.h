#ifndef PCAPFS_LOGGING_H
#define PCAPFS_LOGGING_H

#define BOOST_LOG_DYN_LINK 1

#include <cstdint>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

#define LOG_TRACE   BOOST_LOG_TRIVIAL(trace)
#define LOG_DEBUG   BOOST_LOG_TRIVIAL(debug)
#define LOG_INFO    BOOST_LOG_TRIVIAL(info)
#define LOG_WARNING BOOST_LOG_TRIVIAL(warning)
#define LOG_ERROR   BOOST_LOG_TRIVIAL(error)
#define LOG_FATAL   BOOST_LOG_TRIVIAL(fatal)


namespace pcapfs {
    namespace logging {

        enum class severity : std::int8_t {
            trace = 0,
            debug,
            info,
            warning,
            error,
            fatal
        };

        static bool handed_to_fuse = false;

        void init(severity log_level);

        void profilerFunction(const char* file, const char* function, const char* msg);
        void initProfilerFunction();
        void fuseIsActive();
    }
}

#endif //PCAPFS_LOGGING_H
