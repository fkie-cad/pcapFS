#include "config.h"

#include <algorithm>
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

        for (const auto &opt : *section) {
            if (opt.first == "sortby") {
                const auto sortby = section->get_as<std::string>("sortby");
                if (sortby)
                    config.sortby = *sortby;
            } else
                LOG_WARNING << "Invalid general option in config file: " << opt.first;
        }
    }



    pcapfs::Paths getKeyFiles(const std::shared_ptr<toml::table> &section, const pcapfs::Path &configPath) {
        pcapfs::Paths files;

        for (const auto &entry : *section) {
            if (entry.first != "keyfiles")
                LOG_WARNING << "Invalid keys option in config file: " << entry.first;
            else {
                const auto keyfiles = section->get_array_of<std::string>("keyfiles");
                if (keyfiles) {
                    for (const auto &k : *keyfiles) {
                        boost::filesystem::path path;
                        try {
                            path = boost::filesystem::canonical(k, configPath);
                        } catch (boost::filesystem::filesystem_error &err) {
                            LOG_ERROR << "Invalid key file path in config file: " << err.what();
                            continue;
                        }
                        const auto paths = pcapfs::utils::getFilesFromPath(path, "");
                        files.insert(files.end(), paths.cbegin(), paths.cend());
                    }
                } else {
                    const auto keyfile = section->get_as<std::string>("keyfiles");
                    boost::filesystem::path path;
                    try {
                        path = boost::filesystem::canonical(*keyfile, configPath);
                    } catch (boost::filesystem::filesystem_error &err) {
                        LOG_ERROR << "Invalid key file path in config file: " << err.what();
                        return files;
                    }
                    if (keyfile) {
                        const auto paths = pcapfs::utils::getFilesFromPath(path, "");
                        files.insert(files.end(), paths.cbegin(), paths.cend());
                    }
                }
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


    void parseDecodeSection(const std::shared_ptr<toml::table> &section, ConfigFileOptions &config, const pcapfs::Path &configPath) {
        if (!section) { return; }

        const std::set<std::string> validDecodeTypes = {"xor", "tls", "cobaltstrike"};

        for (const auto &subsection : *section) {
            if (std::find_if(validDecodeTypes.begin(), validDecodeTypes.end(), [subsection](const std::string &s){
                            return subsection.first == s; }) == validDecodeTypes.end()) {
                LOG_WARNING << "Invalid decode type in config file: " << subsection.first;
                continue;
            }

            const auto &subsectionTable = subsection.second->as_table();
            if (!subsectionTable) {
                LOG_WARNING << "Empty decode table in config file";
                continue;
            }
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

                // add xor key files to keyFiles
                if (subsection.first == "xor") {
                    for(const auto &table : properties->get()) {
                        cpptoml::option<std::string> keyfile;
                        try {
                            keyfile = table->get_as<std::string>("keyfile");
                        } catch (std::out_of_range &err) {
                            LOG_ERROR << "No keyfile property provided in xor decode config";
                            continue;
                        }
                        boost::filesystem::path path;
                        try {
                            path = boost::filesystem::canonical(*keyfile, configPath);
                        } catch (boost::filesystem::filesystem_error &err) {
                            LOG_ERROR << "Invalid key file path in config file: " << err.what();
                            continue;
                        }
                        if (keyfile)
                            config.keyFiles.push_back(path);
                    }
                }
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
                    ("config,c", po::value<std::string>(), "config file to use")
                    ("check-non-default-ports", "also try to detect protocols which do not use their default ports")
                    ("help,h", "print this help and exit")
                    ("index,i", po::value<std::string>(), "index file to use")
                    ("in-memory,m", "use an in-memory index")
                    ("keys,k", po::value<std::string>(), "path to a key file or a directory with key files")
                    ("pcap-suffix", po::value<std::string>(&opts.config.pcapSuffix),
                     "take only files from a directory with a matching suffix (e.g. '.pcap')")
                    ("no-cs", "do not try to locate and decrypt cobalt strike traffic")
                    ("no-mount,n", "only create an index file, don't mount the PCAP(s)")
                    ("rewrite,r", "overwrite a possibly existing index file")
                    ("show-all", "also show file which have been parsed already")
                    ("show-metadata", "show meta data files (e.g. HTTP headers)")
                    ("snapshot", po::value<std::string>(),
                    "point in time where to reconstruct SMB share (unix timestamp or time string yyyy-MM-ddTHH:mm:ssZ in UTC)")
                    ("snip", po::value<std::string>()->value_name("<startTime>,<endTime>"),
                    "only display virtual files from the specified network time interval (unix timestamps or time string yyyy-MM-ddTHH:mm:ssZ in UTC)")
                    ("sortby", po::value<std::string>(&(opts.config.sortby))->default_value("/protocol/"),
                     "virtual directory hierarchy to create when mounting the PCAP(s)")
                    ("timestamp-mode", po::value<std::string>()->default_value("hybrid"),
                    "timestamps to set for SMB files (hybrid/fs/network)")
                    ("version,V", "show version information and exit");



            po::typed_value<std::string, char>* verbosity;
            #if(DEBUG)
                verbosity = po::value<std::string>()->default_value("debug");
            #else
                verbosity = po::value<std::string>()->default_value("warning");
            #endif
            pcapfs_options.add_options()
                    ("verbosity,v", verbosity,
                     "set verbosity (valid values are: trace, debug, info, warning, error, fatal)");

            po::options_description fuse_options("FUSE help");
            fuse_options.add_options()
                    ("foreground,f", "foreground operation");

            po::options_description positional_arguments;
            positional_arguments.add_options()
                    ("pcap-path", po::value<std::string>()->required(), "pcap-path")
                    ("mountpoint", po::value<std::string>(), "mountpoint");

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

            opts.config.pcapPath = getSanitizedAsPath(vm["pcap-path"].as<std::string>());
            opts.config.pcaps = pcapfs::utils::getFilesFromPath(opts.config.pcapPath, opts.config.pcapSuffix);

            if (vm.count("mountpoint")) { opts.config.mountpoint = getSanitizedAsPath(vm["mountpoint"].as<std::string>()); }
            if (vm.count("in-memory")) { opts.config.indexInMemory = true; }
            if (vm.count("no-mount")) { opts.config.noMount = true; }
            if (vm.count("rewrite")) { opts.config.rewrite = true; }
            if (vm.count("show-all")) { opts.config.showAll = true; }
            if (vm.count("show-metadata")) { opts.config.showMetadata = true; }
            if (vm.count("no-cs")) { opts.config.noCS = true; }
            if (vm.count("check-non-default-ports")) { opts.config.checkNonDefaultPorts = true; }
            if (vm.count("verbosity")) {
                opts.config.verbosity = getLogLevelFromString(vm["verbosity"].as<std::string>());
            }
            if (vm.count("keys")) {
                const fs::path keyFilePath = getSanitizedAsPath(vm["keys"].as<std::string>());
                const auto keyFiles = pcapfs::utils::getFilesFromPath(keyFilePath, "");
                opts.config.keyFiles.insert(opts.config.keyFiles.end(), keyFiles.cbegin(), keyFiles.cend());
            }
            if(vm.count("index")) { opts.config.indexFilePath = getSanitizedAsPath(vm["index"].as<std::string>()); }

            if (!opts.config.indexInMemory && opts.config.indexFilePath.empty()) {
                opts.config.indexFilePath = boost::filesystem::path(generateIndexFileName());
            }

            if (vm.count("config")) {
                opts.config.configFilePath = getSanitizedAsPath(vm["config"].as<std::string>());
                const auto configFileOptions = pcapfs::options::configfile::parse(opts.config.configFilePath);
                opts.config.decodeMap = configFileOptions.decodeMap;
                if (vm["sortby"].defaulted() && !configFileOptions.sortby.empty()) {
                    opts.config.sortby = configFileOptions.sortby;
                }
                opts.config.keyFiles.insert(opts.config.keyFiles.end(), configFileOptions.keyFiles.cbegin(),
                                            configFileOptions.keyFiles.cend());
            }

            if (vm.count("snapshot")) {
                try {
                    const std::string snapshotString = vm["snapshot"].as<std::string>();
                    if (std::all_of(snapshotString.begin(), snapshotString.end(), ::isdigit)) {
                        long long timestamp = std::stoll(snapshotString);
                        if (timestamp < 0)
                            std::cerr << "Warning: Invalid snapshot timestamp: negative value" << std::endl;
                        else
                            opts.config.snapshot = std::chrono::system_clock::from_time_t(static_cast<std::time_t>(timestamp));
                    } else {
                        std::tm t = {};
                        std::istringstream ss(snapshotString);
                        // e.g. 2024-11-20T13:54:29Z
                        ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%SZ");
                        if (ss.fail()) {
                            std::cerr << "Warning: Failed to parse snapshot timestamp, won't consider it" << std::endl;
                        } else {
                            opts.config.snapshot = std::chrono::system_clock::from_time_t(timegm(&t));
                        }
                    }
                } catch (const std::logic_error&) {
                    std::cerr << "Warning: Invalid snapshot timestamp, won't consider it" << std::endl;
                }
            }

            if (vm.count("snip")) {
                try {
                    const std::string snipString = vm["snip"].as<std::string>();
                    if (std::count(snipString.begin(), snipString.end(), ',') != 1) {
                        std::cerr << "Warning: Invalid format of snip argument, won't consider it" << std::endl;
                    } else {
                        const auto commaPos = snipString.find(',');
                        const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

                        const std::string startSnipString(snipString.begin(), snipString.begin() + commaPos);
                        time_t startSnip{};
                        if (!startSnipString.empty()) {
                            if (std::all_of(startSnipString.begin(), startSnipString.end(), ::isdigit)) {
                                startSnip = static_cast<time_t>(std::stoll(startSnipString));
                            } else {
                                std::tm t = {};
                                std::istringstream ss(startSnipString);
                                // e.g. 2024-11-20T13:54:29Z
                                ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%SZ");
                                if (ss.fail()) {
                                    std::cerr << "Warning: Failed to parse snip timestamp, won't consider it" << std::endl;
                                } else {
                                    startSnip = timegm(&t);
                                }
                            }
                        }

                        const std::string endSnipString(snipString.begin() + commaPos + 1, snipString.end());
                        time_t endSnip{};
                        if (!endSnipString.empty()) {
                            if (std::all_of(endSnipString.begin(), endSnipString.end(), ::isdigit)) {
                                endSnip = static_cast<time_t>(std::stoll(endSnipString));
                            } else {
                                std::tm t = {};
                                std::istringstream ss(endSnipString);
                                // e.g. 2024-11-20T13:54:29Z
                                ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%SZ");
                                if (ss.fail()) {
                                    std::cerr << "Warning: Failed to parse snip timestamp, won't consider it" << std::endl;
                                } else {
                                    endSnip = timegm(&t);
                                }
                            }
                        }

                        if (startSnip < 0 || startSnip > now || endSnip < 0 || endSnip > now || (endSnip != 0 && endSnip <= startSnip)) {
                            std::cerr << "Warning: Invalid snip timestamp(s), won't consider it" << std::endl;
                        } else {
                            opts.config.snip = std::pair<pcapfs::TimePoint, pcapfs::TimePoint>(
                                std::chrono::system_clock::from_time_t(startSnip),
                                std::chrono::system_clock::from_time_t(endSnip)
                            );
                        }

                    }
                } catch(const std::logic_error&) {
                    std::cerr << "Warning: Invalid snip timestamp, won't consider it" << std::endl;
                }
            }

            if (vm.count("timestamp-mode")) {
                const std::string timestampModeString = vm["timestamp-mode"].as<std::string>();
                if (timestampModeString == "fs")
                    opts.config.timestampMode = pcapfs::options::TimestampMode::FS;
                else if (timestampModeString == "network")
                    opts.config.timestampMode = pcapfs::options::TimestampMode::NETWORK;
                else if (timestampModeString != "hybrid")
                    std::cerr << "Warning: invalid timestamp mode, using default mode" << std::endl;
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
        fs::path getSanitizedAsPath(const std::string &filePath) {
            std::string temp(filePath.begin(), filePath.end());
            boost::replace_all(temp, "\\ ", " ");
            return fs::path(temp);
        }

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
    std::transform(args.begin(), args.end(), std::back_inserter(argvVector),
                    [](auto &s){ return &s.front(); });
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

    ConfigFileOptions config;
    std::shared_ptr<toml::table> conf;
    try {
        conf = toml::parse_file(configfile.string());
    } catch (toml::parse_exception &err) {
        LOG_ERROR << "Failed to parse config file: " << err.what();
        return config;
    }
    for (const auto &c : *conf) {
        if (c.first == "general")
            parseGeneralSection(conf->get_table("general"), config);
        else if (c.first == "keys")
            parseKeysSection(conf->get_table("keys"), config, configfile.parent_path());
        else if (c.first == "decode")
            parseDecodeSection(conf->get_table("decode"), config, configfile.parent_path());
        else
            LOG_WARNING << "Invalid config file option: " << c.first;
    }
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
