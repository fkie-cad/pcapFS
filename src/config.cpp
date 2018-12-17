#include "config.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <cpptoml.h>

#include "exceptions.h"
#include "fuse.h"
#include "utils.h"
#include "versions.h"


namespace {

    namespace fs = boost::filesystem;
    namespace po = boost::program_options;
    namespace toml = cpptoml;

    using pcapfs::options::ConfigFileOptions;


    class PropertiesConfigVisitor {
    public:
        void visit(const toml::table_array &table_array) {
            decodeMapEntry.clear();
            for (const auto &ta : table_array) {
                ta->accept(*this);
            }
        }

        void visit(const toml::table &table) {
            decodeMapEntry.emplace_back();
            for (const auto &t : table) {
                currentKey = t.first;
                t.second->accept(*this);
            }
        }

        void visit(const toml::value<std::string> &v) {
            decodeMapEntry.back()[currentKey] = v.get();
        }

        void visit(const toml::value<int64_t> &v) {
            decodeMapEntry.back()[currentKey] = std::to_string(v.get());
        }

        pcapfs::DecodeMapEntry getDecodeMapEntry() const {
            return decodeMapEntry;
        };

        void visit(const toml::value<toml::local_date> &) {}

        void visit(const toml::value<toml::local_time> &) {}

        void visit(const toml::value<toml::local_datetime> &) {}

        void visit(const toml::value<toml::offset_datetime> &) {}

        void visit(const toml::value<bool> &) {}

        void visit(const toml::value<double> &) {}

        void visit(const toml::array &) {}

    private:
        pcapfs::DecodeMapEntry decodeMapEntry;
        std::string currentKey;
    };


    void parseGeneralSection(const std::shared_ptr<toml::table> &section, ConfigFileOptions &config) {
        if (!section) { return; }
        const auto sortby = section->get_as<std::string>("sortby");
        if (sortby) {
            config.sortby = *sortby;
        }
    }


    pcapfs::Paths getKeyFiles(const std::shared_ptr<toml::table> &section, const pcapfs::Path &configPath) {
        pcapfs::Paths files;
        const auto keyfiles = section->get_array_of<std::string>("keyfiles");
        if (keyfiles) {
            for (const auto &k : *keyfiles) {
                const auto path = boost::filesystem::canonical(k, configPath);
                const auto paths = pcapfs::utils::getFilesFromPath(path, "");
                files.insert(files.end(), paths.cbegin(), paths.cend());
            }
        } else {
            const auto keyfile = section->get_as<std::string>("keyfiles");
            const auto path = boost::filesystem::canonical(*keyfile, configPath);
            if (keyfile) {
                const auto paths = pcapfs::utils::getFilesFromPath(path, "");
                files.insert(files.end(), paths.cbegin(), paths.cend());
            }
        }
        return files;
    }


    void parseKeysSection(const std::shared_ptr<toml::table> &section, ConfigFileOptions &config,
                          const pcapfs::Path &configPath) {
        if (!section) { return; }
        const auto keyFilePaths = getKeyFiles(section, configPath);
        config.keyFiles.insert(config.keyFiles.end(), keyFilePaths.cbegin(), keyFilePaths.cend());
    }


    pcapfs::DecodeMapEntry parseDecodeMapEntryFromPropertyList(const toml::table_array &properties) {
        PropertiesConfigVisitor visitor;
        properties.accept(visitor);
        return visitor.getDecodeMapEntry();
    }


    void parseDecodeSection(const std::shared_ptr<toml::table> &section, ConfigFileOptions &config) {
        if (!section) { return; }

        for (const auto &subsection : *section) {
            const auto &subsectionTable = subsection.second->as_table();
            const auto &subsectionKey = subsectionTable->get_as<std::string>("withKey");
            if (subsectionKey) {
                //TODO
            }

            const auto &properties = subsectionTable->get_table_array("properties");
            if (properties) {
                if (!properties->is_table_array()) {  //TODO: fix this check work!
                    throw pcapfs::ConfigFileError(
                            "properties have to be specified using a TOML list. Maybe you forgot "
                            "to use double brackets?");
                }
                config.decodeMap[subsection.first] = parseDecodeMapEntryFromPropertyList(*properties);
            }
        }
    }


    pcapfs::logging::severity getLogLevelFromString(const std::string &logLevelString) {
        const auto s = boost::algorithm::to_lower_copy(logLevelString);
        if (s == "trace") {
            return pcapfs::logging::severity::trace;
        } else if (s == "debug") {
            return pcapfs::logging::severity::debug;
        } else if (s == "info") {
            return pcapfs::logging::severity::info;
        } else if (s == "warning" || s == "warn") {
            return pcapfs::logging::severity::warning;
        } else if (s == "error") {
            return pcapfs::logging::severity::error;
        } else if (s == "fatal") {
            return pcapfs::logging::severity::fatal;
        } else {
            throw pcapfs::ArgumentError("'" + logLevelString + "' is not a valid verbosity.");
        }
    }


    const std::string generateIndexFileName() {
        auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << std::put_time(std::localtime(&t), "%Y%m%d-%H%M%S");
        return ss.str() + "_pcapfs.index";
    }


    class CommandLineParser {
    public:
        CommandLineParser()
                : options(), visible_options("Usage: pcapfs [options] <pcapfile|pcapdir> <mountpoint>"), opts() {
            po::options_description pcapfs_options("pcapFS help");
            pcapfs_options.add_options()
                    ("config,c", po::value<fs::path>(&opts.config.configFilePath), "config file to use")
                    ("help,h", "print this help and exit")
                    ("index,i", po::value<fs::path>(&(opts.config.indexFilePath)), "index file to use")
                    ("in-memory,m", "use an in-memory index")
                    ("keys,k", po::value<fs::path>(), "path to a key file or a directory with key files")
                    ("pcap-suffix", po::value<std::string>(&opts.config.pcapSuffix),
                     "take only files from a directory with a matching suffix (e.g. '.pcap')")
                    ("no-mount,n", "only create an index file, don't mount the PCAP(s)")
                    ("rewrite,r", "overwrite a possibly existing index file")
                    ("show-all", "also show file which have been parsed already")
                    ("show-metadata", "show meta data files (e.g. HTTP headers)")
                    ("sortby", po::value<std::string>(&(opts.config.sortby))->default_value("/protocol/"),
                     "virtual directory hierarchy to create when mounting the PCAP(s)")
                    ("verbosity,v", po::value<std::string>()->default_value("warning"),
                     "set verbosity (valid values are: trace, debug, info, warning, error, fatal)")
                    ("version,V", "show version information and exit");

            po::options_description fuse_options("FUSE help");
            fuse_options.add_options()
                    ("foreground,f", "foreground operation");

            po::options_description positional_arguments;
            positional_arguments.add_options()
                    ("pcap-path", po::value<fs::path>(&(opts.config.pcapPath))->required(), "pcap-path")
                    ("mountpoint", po::value<fs::path>(&(opts.config.mountpoint)), "mountpoint");

            options.add(pcapfs_options).add(fuse_options).add(positional_arguments);
            visible_options.add(pcapfs_options).add(fuse_options);
        }

        const pcapfs::options::CommandLineOptions parse(int argc, const char *argv[]) {
            po::positional_options_description positionals;
            positionals.add("pcap-path", 1);
            positionals.add("mountpoint", 1);
            po::variables_map vm;

            try {
                po::store(po::command_line_parser(argc, argv).options(options).positional(positionals).run(), vm);
            } catch (std::exception &e) {
                throw pcapfs::ArgumentError(e.what());
            }

            if (vm.count("help")) { opts.showHelp = true; }
            if (vm.count("version")) { opts.showVersion = true; }
            if (opts.showHelp || opts.showVersion) { return opts; }

            try {
                po::notify(vm);
            } catch (std::exception &e) {
                throw pcapfs::ArgumentError(e.what());
            }

            opts.config.pcapPath = vm["pcap-path"].as<fs::path>();
            opts.config.pcaps = pcapfs::utils::getFilesFromPath(vm["pcap-path"].as<fs::path>(), opts.config.pcapSuffix);

            if (vm.count("mountpoint")) { opts.config.mountpoint = vm["mountpoint"].as<fs::path>(); }
            if (vm.count("in-memory")) { opts.config.indexInMemory = true; }
            if (vm.count("no-mount")) { opts.config.noMount = true; }
            if (vm.count("rewrite")) { opts.config.rewrite = true; }
            if (vm.count("show-all")) { opts.config.showAll = true; }
            if (vm.count("show-metadata")) { opts.config.showMetadata = true; }
            if (vm.count("verbosity")) {
                opts.config.verbosity = getLogLevelFromString(vm["verbosity"].as<std::string>());
            }
            if (vm.count("keys")) {
                opts.config.keyFiles = pcapfs::utils::getFilesFromPath(vm["keys"].as<fs::path>(), "");
            }

            if (!opts.config.indexInMemory && opts.config.indexFilePath.empty()) {
                opts.config.indexFilePath = boost::filesystem::path(generateIndexFileName());
            }

            if (!opts.config.configFilePath.empty()) {
                const auto configFileOptions = pcapfs::options::configfile::parse(opts.config.configFilePath);
                opts.config.decodeMap = configFileOptions.decodeMap;
                if (vm["sortby"].defaulted() && !configFileOptions.sortby.empty()) {
                    opts.config.sortby = configFileOptions.sortby;
                }
                opts.config.keyFiles.insert(opts.config.keyFiles.end(), configFileOptions.keyFiles.cbegin(),
                                            configFileOptions.keyFiles.cend());
            }

            // Prepare the options to be forwarded to FUSE:
            if (vm.count("foreground")) { opts.fuseArgs.add("-f"); }
            opts.fuseArgs.add("-s");    //TODO: check if this really causes problems
            opts.fuseArgs.add(opts.config.mountpoint.string());

            return opts;
        };

        void printHelp() const {
            std::cout << visible_options;
            std::cout << std::endl << std::endl;
        };

        void printVersion() const {
            std::cout << "pcapFS version: " << PCAPFS_VERSION << std::endl;
            std::cout << "pcapFS index version: " << PCAPFS_INDEX_VERSION_MAJOR << "." << PCAPFS_INDEX_VERSION_MINOR
                      << std::endl;
            std::cout << "FUSE library version: " << fuse_pkgversion() << std::endl;
            fuse_lowlevel_version();
        };

    private:
        boost::program_options::options_description options;
        boost::program_options::options_description visible_options;
        pcapfs::options::CommandLineOptions opts;
    };

}


void pcapfs::options::PcapFsOptions::validate() const {
    using pcapfs::ArgumentError;
    if (pcaps.empty()) {
        throw ArgumentError("No PCAP file(s) provided.");
    }
    if (mountpoint.empty() and !noMount) {
        throw ArgumentError(
                "No mount point provided. This is only valid in combination with the --no-mount option.");
    }
}


pcapfs::options::FuseOptions::FuseOptions() : args{"pcapFS"}, argvVector() {}


int pcapfs::options::FuseOptions::argc() const {
    return static_cast<int>(args.size());
}


char **pcapfs::options::FuseOptions::argv() {
    argvVector.clear();
    for (auto &s : args) {
        argvVector.push_back(&s.front());
    }
    return argvVector.data();
}


void pcapfs::options::FuseOptions::add(const std::string &option) {
    args.push_back(option);
}


const pcapfs::options::CommandLineOptions pcapfs::options::commandline::parse(int argc, const char **argv) {
    CommandLineParser parser;
    return parser.parse(argc, argv);
}


void pcapfs::options::commandline::printHelp() {
    CommandLineParser().printHelp();
}


void pcapfs::options::commandline::printVersion() {
    CommandLineParser().printVersion();
}


const pcapfs::options::ConfigFileOptions pcapfs::options::configfile::parse(const pcapfs::Path &configfile) {
    if (!fs::is_regular_file(configfile)) {
        throw pcapfs::ArgumentError("Configuration file '" + configfile.string() +
                                    "' does not exists or is not a regular file.");
    }
    const auto conf = toml::parse_file(configfile.string());
    ConfigFileOptions config;
    parseGeneralSection(conf->get_table("general"), config);
    parseKeysSection(conf->get_table("keys"), config, configfile.parent_path());
    parseDecodeSection(conf->get_table("decode"), config);
    return config;
}


pcapfs::Configuration pcapfs::parseOptions(int argc, const char **argv) {
    const auto commandLineOptions = options::commandline::parse(argc, argv);
    Configuration config;
    config.pcapfsOptions = commandLineOptions.config;
    config.fuseOptions = commandLineOptions.fuseArgs;
    config.showHelp = commandLineOptions.showHelp;
    config.showVersion = commandLineOptions.showVersion;
    return config;
}


void pcapfs::assertValidOptions(const pcapfs::Configuration &config) {
    config.pcapfsOptions.validate();
}
