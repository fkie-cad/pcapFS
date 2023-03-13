#ifndef PCAPFS_INDEX_H
#define PCAPFS_INDEX_H

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "commontypes.h"
#include "file.h"
#include "offsets.h"


namespace pcapfs {

    class File;

    typedef std::shared_ptr<File> FilePtr;

    namespace index {
        typedef std::pair<std::string, uint64_t> IndexPosition;
    }

    class Index {
    public:
        Index();

        pcapfs::FilePtr get(const pcapfs::index::IndexPosition &idxPosition) const;

        std::vector<pcapfs::FilePtr> getFiles() const;

        void insert(const pcapfs::FilePtr &filePtr);

        void insert(const std::vector<pcapfs::FilePtr> &files);

        void insertPcaps(const std::vector<pcapfs::FilePtr> &files);

        void insertKeyCandidates(const std::vector<pcapfs::FilePtr> &files);

        void write(const Path &path) const;

        void read(const Path &path);

        void setCurrentWorkingDirectory(const std::string &cwd) { currentWorkingDirectory = cwd; };

        const std::string getCurrentWorkingDirectory() const { return currentWorkingDirectory; };

        std::vector<pcapfs::FilePtr> getCandidatesOfType(const std::string &type) const;

        void assertCorrectPcaps(const std::vector<pcapfs::FilePtr> &pcaps);

    private:
        std::string currentWorkingDirectory;

        std::unordered_map<std::string, uint64_t> counter;
        std::unordered_map<std::string, FilePtr> files;
        std::vector<pcapfs::FilePtr> storedPcaps;

        uint64_t getNextID(const std::string &type);

        void increaseID(const std::string &type);

        std::unordered_map<std::string, std::vector<FilePtr>> keyCandidates;
    };

}

#endif //PCAPFS_INDEX_H
