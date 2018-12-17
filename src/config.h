#ifndef PCAPFS_CONFIG_H
#define PCAPFS_CONFIG_H

#include <string>
#include <vector>

#include "commontypes.h"
#include "decodemap.h"
#include "logging.h"


namespace pcapfs {
    namespace options {

        struct PcapFsOptions {
            Path indexFilePath;
            Path configFilePath;
            Path pcapPath;
            Path mountpoint;
            Paths pcaps;
            Paths keyFiles;
            std::string sortby;
            std::string pcapSuffix;
            logging::severity verbosity = logging::severity::warning;
            bool rewrite = false;
            bool noMount = false;
            bool showMetadata = false;
            bool showAll = false;
            bool indexInMemory = false;
            DecodeMap decodeMap;

            const DecodeMapEntry getDecodeMapFor(const std::string &file) { return decodeMap[file]; };

            void validate() const;
        };


        struct FuseOptions {
            FuseOptions();

            int argc() const;

            char **argv();

            void add(const std::string &option);

        private:
            std::vector<std::string> args;
            std::vector<char *> argvVector;
        };


        struct CommandLineOptions {
            bool showHelp = false;
            bool showVersion = false;
            FuseOptions fuseArgs;
            PcapFsOptions config;
        };


        struct ConfigFileOptions {
            std::string sortby;
            Paths keyFiles;
            DecodeMap decodeMap;
        };


        namespace commandline {
            const CommandLineOptions parse(int argc, const char *argv[]);

            void printHelp();

            void printVersion();
        }


        namespace configfile {
            const ConfigFileOptions parse(const Path &configfile);
        }

    }

    struct Configuration {
        options::PcapFsOptions pcapfsOptions;
        options::FuseOptions fuseOptions;
        bool showHelp = false;
        bool showVersion = false;
    };


    Configuration parseOptions(int argc, const char *argv[]);

    void assertValidOptions(const Configuration &config);
}

#endif //PCAPFS_CONFIG_H
