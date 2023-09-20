#ifndef PCAPFS_EXCEPTIONS_H
#define PCAPFS_EXCEPTIONS_H

#include <stdexcept>
#include <string>


namespace pcapfs {

    class PcapFsException : public std::runtime_error {
    public:
        explicit PcapFsException(const std::string &what) : std::runtime_error(what) {}
    };


    class ConfigurationError : public PcapFsException {
    public:
        explicit ConfigurationError(const std::string &what) : PcapFsException(what) {}
    };


    class ArgumentError : public ConfigurationError {
    public:
        explicit ArgumentError(const std::string &what) : ConfigurationError(what) {}
    };


    class ConfigFileError : public ConfigurationError {
    public:
        explicit ConfigFileError(const std::string &what) : ConfigurationError(what) {}
    };


    class IndexError : public PcapFsException {
    public:
        explicit IndexError(const std::string &what) : PcapFsException(what) {}
    };

    class SmbError : public PcapFsException {
    public:
        explicit SmbError(const std::string &what) : PcapFsException(what) {}
    };

    class SmbSizeError : public SmbError {
    public:
        explicit SmbSizeError(const std::string &what) : SmbError(what) {}
    };

}

#endif //PCAPFS_EXCEPTIONS_H
