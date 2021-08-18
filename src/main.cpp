#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include "commontypes.h"
#include "exceptions.h"
#include "file.h"
#include "index.h"
#include "offsets.h"
#include "logging.h"
#include "pcapfs.h"
#include "dirlayout.h"
#include "capturefiles/capturefile.h"
#include "keyfiles/sslkey.h"
#include "keyfiles/xorkey.h"
#include "virtualfiles/tcp.h"
#include "virtualfiles/udp.h"
#include "virtualfiles/xor.h"
#include "capturefiles/pcap.h"


namespace fs = boost::filesystem;

/*
 * This function is entered for all *filesToProcess* candidates and to handle the new *newFiles*
 * which occur after this function *getNextVirtualFile* detects new candidates.
 * This happens e.g. when SSL Files are first parsed as TCP files and then as HTTP content files
 * after the decryption stage. It happens that the functions are called twice or in theory even more often.
 */
std::pair<std::vector<pcapfs::FilePtr>, std::vector<pcapfs::FilePtr>>
getNextVirtualFile(const std::vector<pcapfs::FilePtr> files, pcapfs::Index &idx) {
    std::vector<pcapfs::FilePtr> filesToProcess;
    std::vector<pcapfs::FilePtr> newFiles;

    pcapfs::logging::profilerFunction(__FILE__, __FUNCTION__, "was called");

    for (auto &file: files) {
        if (file->flags.test(pcapfs::flags::IS_REAL_FILE)) {
            continue;
        }

        LOG_TRACE << "current file name: " << file->getFilename() <<
        		" fileSizeRaw: " << file->getFilesizeRaw() <<
				" fileSizeProcessed: " << file->getFilesizeProcessed();

        file->fillBuffer(idx);
        std::vector<pcapfs::FilePtr> newPtr(0);
        for (auto &it: pcapfs::FileFactory::getFactoryParseMethods()) {
            if (file->getFiletype() != it.first) {
            	/*
            	 * Debug helpers for this construct here is necessary
            	 */
                newPtr = it.second(file, idx);

                LOG_TRACE << file->to_string();

                if (!newPtr.empty()) {
                    file->flags.set(pcapfs::flags::PARSED);
                    filesToProcess.insert(filesToProcess.end(), newPtr.begin(), newPtr.end());
                    newFiles.insert(newFiles.end(), newPtr.begin(), newPtr.end());
                    file->clearBuffer();
                    break;
                }
            }
        }

        if (!file->flags.test(pcapfs::flags::PARSED)) {
            filesToProcess.push_back(file);
        }
        file->clearBuffer();
    }
    return std::make_pair(newFiles, filesToProcess);
}


int main(int argc, const char *argv[]) {

    pcapfs::Configuration options;
    try {
        options = pcapfs::parseOptions(argc, argv);
    } catch (pcapfs::ArgumentError &e) {
        pcapfs::options::commandline::printHelp();
        std::cerr << e.what() << std::endl;
        std::cerr << "See help message above for usage information." << std::endl;
        return 1;
    }

    if (options.showHelp || options.showVersion) {
        if (options.showHelp) { pcapfs::options::commandline::printHelp(); }
        if (options.showVersion) { pcapfs::options::commandline::printVersion(); }
        return EXIT_SUCCESS;
    }

    pcapfs::assertValidOptions(options);
    auto config = options.pcapfsOptions;
    pcapfs::logging::init(config.verbosity);
    pcapfs::File::setConfig(config);

    pcapfs::Index index;
    index.setCurrentWorkingDirectory(boost::filesystem::current_path().string());
    std::vector<pcapfs::FilePtr> pcapFiles = pcapfs::PcapFile::createFromPaths(config.pcaps);

    //TODO: use factory as well (only get key vfiles)
    if (!config.keyFiles.empty()) {
        std::vector<pcapfs::FilePtr> keyFiles = pcapfs::SSLKeyFile::parseCandidates(config.keyFiles);
        index.insertKeyCandidates(keyFiles);
        keyFiles = pcapfs::XORKeyFile::parseCandidates(config.keyFiles);
        index.insertKeyCandidates(keyFiles);
    }

    if (config.indexInMemory) { LOG_INFO << "Using an in-memory index"; }

    //TODO: needs to check the index file here as well, if it matches the pcaps


    /*
     * Here we process all content from the pcaps:
     *
     * TCP and UDP files are created and added to the index.
     * Then all files are added to *filesToProcess*.
     * *newfiles* will contain new virtual files we get from processing.
     *
     * std::tie is used to unpack the returned tuple from *getNextVirtualFile*,
     * *std::pair* is returned. Then we have new files added to the index.
     * This is done *UNTIL* new files is empty, whcih means it is possible that
     * functions are called more than one time.
     *
     */
    if (!fs::is_regular_file(config.indexFilePath) ||
        (fs::is_regular_file(config.indexFilePath) && (fs::is_empty(config.indexFilePath) || config.rewrite))) {
        LOG_TRACE << "Creating index";

        index.insertPcaps(pcapFiles);
        std::vector<pcapfs::FilePtr> tcpFiles = pcapfs::TcpFile::createVirtualFilesFromPcaps(pcapFiles);
        index.insert(tcpFiles);
        std::vector<pcapfs::FilePtr> udpFiles = pcapfs::UdpFile::createUDPVirtualFilesFromPcaps(pcapFiles);
        index.insert(udpFiles);
        std::vector<pcapfs::FilePtr> filesToProcess = index.getFiles();
        std::vector<pcapfs::FilePtr> newFiles;

        int counter = 0;

        LOG_TRACE << "PROGRESS("<< counter << "): <newfiles|filesToProcess> <" << newFiles.size() << "|"
        		<< filesToProcess.size() << ">";

        /*
         * Every file is created as TCP or UDP File
         * Both file types are handled by the getNextVirtualFile function,
         * which gets all TCP and UDP files.
         * They are iteratively added and reprocessed until no new files are left
         */
        do {
            counter++;
            std::tie(newFiles, filesToProcess) = getNextVirtualFile(filesToProcess, index);
            index.insert(newFiles);
            LOG_TRACE << "PROGRESS("<< counter << "): <newfiles|filesToProcess> <" << newFiles.size() << "|"
            		<< filesToProcess.size() << ">";
        } while (!newFiles.empty());

        LOG_TRACE << "PROGRESS("<< counter << "): <newfiles|filesToProcess> <" << newFiles.size() << "|"
        		<< filesToProcess.size() << ">";

        if (!config.indexInMemory) {
            index.write(config.indexFilePath);
            LOG_INFO << "Wrote index to file " << config.indexFilePath.string();
        }

    } else {
        LOG_INFO << "Reading from index file " << config.indexFilePath.string();
        try {
            index.read(config.indexFilePath);
            index.assertCorrectPcaps(pcapFiles);
        } catch (const pcapfs::IndexError &err) {
            std::cerr << "Error: " << err.what() << std::endl;
            return 2;
        }

    }


    /*
     * The actual filesystem part is happening here:
     */
    if (config.noMount) {
        LOG_INFO << "Exiting because no-mount option was given";
        return EXIT_SUCCESS;
    } else {
        pcapfs_filesystem::DirectoryLayout::initFilesystem(index, config.sortby);
        pcapfs::PcapFs fs(index);
        //TODO: LOG levels don't seem to be the same... output of LOG_TRACE here is not there
        LOG_INFO << "Mounting PCAP file(s)";
        return fs.run(options.fuseOptions.argc(), options.fuseOptions.argv());
    }
}
