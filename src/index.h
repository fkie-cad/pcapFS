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
        typedef std::pair<std::string, uint64_t> indexPosition;
    }

    class Index {
    public:
        Index();

        pcapfs::FilePtr get(const pcapfs::index::indexPosition &) const;

        std::vector<pcapfs::FilePtr> getFiles() const;

        void insert(pcapfs::FilePtr filePtr);

        void insert(std::vector<pcapfs::FilePtr> &files);

        void insertKeyCandidates(std::vector<pcapfs::FilePtr> &files);

        void write(const Path &path);

        void read(const Path &path);

        void setCurrentWorkingDirectory(const std::string &cwd) { currentWorkingDirectory = cwd; };

        const std::string getCurrentWorkingDirectory() const { return currentWorkingDirectory; };

        std::vector<pcapfs::FilePtr> getCandidatesOfType(const std::string &type) const;

        uint64_t getNextID(const std::string &type);

    private:
        std::string currentWorkingDirectory;

        std::unordered_map<std::string, uint64_t> counter;
        std::unordered_map<std::string, FilePtr> files;

        void increaseID(const std::string &type);

        //used for key candidates
        //TODO: use a map to make the search more effective?
        std::unordered_map<std::string, std::vector<FilePtr>> keyCandidates;
    };

}

#endif //PCAPFS_INDEX_H
