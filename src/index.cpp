#include "index.h"

#include <iomanip>
#include <iostream>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/serialization/collection_size_type.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/utility.hpp>

#include "exceptions.h"
#include "filefactory.h"
#include "logging.h"
#include "capturefiles/capturefile.h"
#include "versions.h"
#include "virtualfiles/serverfile.h"


namespace {

    typedef std::pair<uint16_t, uint16_t> IndexVersion;

    const char *PCAPFS_INDEX_MAGIC_STRING = "PCAPFS_INDEX";
    typedef uint16_t VersionComponent;
    const VersionComponent PCAPFS_INDEX_MAJOR_VERSION = PCAPFS_INDEX_VERSION_MAJOR;
    const VersionComponent PCAPFS_INDEX_MINOR_VERSION = PCAPFS_INDEX_VERSION_MINOR;


    struct IndexHeader {
    public:
        std::string magicString{PCAPFS_INDEX_MAGIC_STRING};
        IndexVersion version{PCAPFS_INDEX_MAJOR_VERSION, PCAPFS_INDEX_MINOR_VERSION};
        std::string pcapfsVersion{PCAPFS_VERSION};

        const std::string getIndexVersionString() const {
            return std::to_string(version.first) + "." + std::to_string(version.second);
        }

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & magicString;
            archive & version;
            archive & pcapfsVersion;
        }
    };


    void assertIndexHeaderIsCompatible(const IndexHeader &header) {
        if ((header.version.first >= 1 && header.version.first > PCAPFS_INDEX_MAJOR_VERSION) ||
            (header.version.first < 1 && header.version.second > PCAPFS_INDEX_MINOR_VERSION)) {
            throw pcapfs::IndexError(
                    "Incompatible index version! The version of the index you tried to read is " +
                    header.getIndexVersionString() + " while the version of pcapFS you are using supports only " +
                    "index versions up to " + IndexHeader().getIndexVersionString() + ".");
        }
    }

}


pcapfs::Index::Index() : currentWorkingDirectory("") {}


pcapfs::FilePtr pcapfs::Index::get(const pcapfs::index::IndexPosition &idxPosition) const {
    try {
        return files.at(idxPosition.first + std::to_string(idxPosition.second));
    } catch (std::out_of_range &e) {
        const std::string msg = idxPosition.first + std::to_string(idxPosition.second) + " not found in index!";
        throw IndexError(msg);
    }
}


uint64_t pcapfs::Index::getNextID(const std::string &type) {
    return counter[type];
}


std::vector<pcapfs::FilePtr> pcapfs::Index::getFiles() const {
    std::vector<pcapfs::FilePtr> result;
    std::transform(files.cbegin(), files.cend(), std::back_inserter(result),
                    [](const auto &mapEntry){ return mapEntry.second; });
    return result;
}


void pcapfs::Index::increaseID(const std::string &type) {
    counter[type] += 1;
}


void pcapfs::Index::insert(const pcapfs::FilePtr &filePtr) {
    if (filePtr == nullptr) {
        return;
    }
    std::string key = filePtr->getFiletype();

    if (filePtr->getIdInIndex() != 0) {
        key += std::to_string(filePtr->getIdInIndex());
    } else {
        uint64_t nextID = getNextID(filePtr->getFiletype());
        key += std::to_string(nextID);
        filePtr->setIdInIndex(nextID);
        increaseID(filePtr->getFiletype());
    }
    files.insert({key, filePtr});
}


void pcapfs::Index::insert(const std::vector<pcapfs::FilePtr> &ptrFiles) {
    for (const auto &ptrFile: ptrFiles) {
        insert(ptrFile);
    }
}


void pcapfs::Index::insertPcaps(const std::vector<pcapfs::FilePtr> &ptrFiles) {
    for (const auto &ptrFile: ptrFiles) {
        storedPcaps.push_back(ptrFile);
        insert(ptrFile);
    }
}


void pcapfs::Index::insertKeyCandidates(const std::vector<pcapfs::FilePtr> &files) {
    for (const auto &keyFile: files) {
        keyCandidates[keyFile->getFiletype()].push_back(keyFile);
    }
}


std::vector<pcapfs::FilePtr> pcapfs::Index::getCandidatesOfType(const std::string &type) const {
    auto it = keyCandidates.find(type);
    if (it == keyCandidates.end()) {
        return std::vector<pcapfs::FilePtr>();
    } else {
        return it->second;
    }
}


void pcapfs::Index::write(const pcapfs::Path &path) const {
    for (const auto &storedPcap : storedPcaps) {
        boost::filesystem::path p(storedPcap->getFilename());
        storedPcap->setFilename(p.filename().string());
    }
    std::stringstream indexOutput;
    boost::archive::text_oarchive archive(indexOutput);
    IndexHeader header;
    archive << header;
    const uint64_t numberOfFiles = files.size();
    archive << numberOfFiles;
    for (const auto &file: files) {
        archive << file.first;
        file.second->serialize(archive);
    }
    namespace bio = boost::iostreams;
    std::ofstream of(path.string(), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
    bio::filtering_ostreambuf out;
    out.push(bio::gzip_compressor());
    out.push(of);
    bio::copy(indexOutput, out);
}


void pcapfs::Index::read(const pcapfs::Path &path) {
    std::ifstream f(path.string(), std::ios_base::in | std::ios_base::binary);
    if (f.fail()) {
        throw IndexError("Index could not be opened for reading");
    }
    namespace bio = boost::iostreams;
    std::stringstream inputIndex;
    bio::filtering_istreambuf out;
    out.push(bio::gzip_decompressor());
    out.push(f);
    bio::copy(out, inputIndex);
    f.close();

    boost::archive::text_iarchive archive(inputIndex);

    IndexHeader header;
    archive >> header;
    assertIndexHeaderIsCompatible(header);

    uint64_t numberOfFiles;
    archive >> numberOfFiles;

    FilePtr currentPtr;
    std::string type;
    std::string indexFilename;
    for (uint64_t i = 0; i < numberOfFiles; ++i) {
        archive >> indexFilename;
        archive >> type;
        currentPtr = pcapfs::FileFactory::createFilePtr(type);
        if (!currentPtr) {
            throw IndexError("File of type " + type + " couldnot be created");
        }
        currentPtr->deserialize(archive);
        currentPtr->filetype = type;
        if (type == "pcap" || type == "pcapng") {
            storedPcaps.push_back(currentPtr);
        }
        files.insert({indexFilename, currentPtr});
    }

    // set parent dirs for serverfiles
    for (const auto &entry : files) {
        if (entry.second->isFiletype("smb")) {
            ServerFilePtr serverFilePtr = std::static_pointer_cast<ServerFile>(entry.second);
            const uint64_t parentDirId = serverFilePtr->getParentDirId();
            if (parentDirId != (uint64_t)-1) {
                serverFilePtr->setParentDir(get({"smb", parentDirId}));
            } else {
                serverFilePtr->setParentDir(nullptr);
            }
        } else if (entry.second->isFiletype("ftp")) {
            ServerFilePtr serverFilePtr = std::static_pointer_cast<ServerFile>(entry.second);
            const uint64_t parentDirId = serverFilePtr->getParentDirId();
            if (parentDirId != (uint64_t)-1) {
                serverFilePtr->setParentDir(get({"ftp", parentDirId}));
            } else {
                serverFilePtr->setParentDir(nullptr);
            }
        }
    }
}


void pcapfs::Index::assertCorrectPcaps(const std::vector<pcapfs::FilePtr> &pcaps) {
    for (const auto &storedPcap : storedPcaps) {
        bool available = false;
        for (const auto &pcap : pcaps) {
            boost::filesystem::path p(pcap->getFilename());
            if (p.filename() == storedPcap->getFilename()) {
                if (pcap->getFilesizeRaw() == storedPcap->getFilesizeRaw()) {
                    available = true;
                    storedPcap->setFilename(pcap->getFilename());
                    break;
                } else {
                    LOG_ERROR << "sizes of pcap " << storedPcap->getFilename() << " don't match!";
                    LOG_ERROR << "expected " << std::to_string(storedPcap->getFilesizeRaw()) << " bytes, got " <<
                              pcap->getFilesizeRaw();
                }
            }
        }
        if (!available) {
            LOG_ERROR << "couldn't find pcap " << storedPcap->getFilename() << "!";
            throw pcapfs::IndexError("couldn't find pcap " + storedPcap->getFilename() + "!");
        }
    }
}
