#include "logging.h"

#include <iostream>
#include <fstream>

#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>


namespace pcapfs {
    namespace logging {

        boost::log::trivial::severity_level get_log_level(severity log_level) {
            switch (log_level) {
                case severity::trace :
                    return boost::log::trivial::trace;
                case severity::debug :
                    return boost::log::trivial::debug;
                case severity::info :
                    return boost::log::trivial::info;
                case severity::warning :
                    return boost::log::trivial::warning;
                case severity::error :
                    return boost::log::trivial::error;
                case severity::fatal :
                    return boost::log::trivial::fatal;
                default:
                    return boost::log::trivial::warning;
            }
        }

    }
}

void pcapfs::logging::fuseIsActive() {
	handed_to_fuse = true;
}

void pcapfs::logging::init(const pcapfs::logging::severity log_level) {
    namespace expr = boost::log::expressions;
    boost::log::add_common_attributes();

    const auto format = (boost::log::expressions::stream
    		<< expr::attr<unsigned int>("LineID") << " | "
            << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f") << " | "
            << boost::log::trivial::severity << " | "
            << expr::smessage);
    const auto sink = boost::log::add_console_log(std::clog, boost::log::keywords::format = format);
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= get_log_level(log_level));
}


void pcapfs::logging::initProfilerFunction() {
	const char* target = "profiler.csv";
	std::ofstream target_output_file;
	target_output_file.open(target, std::ios_base::out | std::ios_base::trunc);
	target_output_file << "duration;timestamp;file;function;message;status" << std::endl;
	LOG_TRACE << "[PROFILING]" << "timestamp;file;function;message;status" << std::endl;
	target_output_file.close();
}


void pcapfs::logging::profilerFunction(const char* file, const char* function, const char* msg) {
	std::time_t result = std::time(nullptr);
	const char* target = "profiler.csv";
	std::ofstream target_output_file;
	target_output_file.open(target, std::ios_base::out | std::ios_base::app);
	target_output_file << "" << ";" << result << ";" << file << ";" << function << ";" << msg << ";" << handed_to_fuse << std::endl;
	LOG_TRACE << "[PROFILING]" <<  result << ";" << file << ";" << function << ";" << msg << ";" << handed_to_fuse << std::endl;
	target_output_file.close();
}
