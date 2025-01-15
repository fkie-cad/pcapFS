#ifndef PCAPFS_VIRTUAL_FILES_SERVER_FILE_MANAGER_H
#define PCAPFS_VIRTUAL_FILES_SERVER_FILE_MANAGER_H

#include "serverfile.h"

namespace pcapfs {

    // base struct for (if necessary) identifiers in the serverFiles map
    struct ServerFileTree {
        bool operator==(const ServerFileTree &) const { return true; };
        bool operator<(const ServerFileTree &) const { return false; };
    };

    const ServerFileTree SERVER_FILE_TREE_DUMMY;


    class ServerFileManager {
    public:
        virtual ~ServerFileManager() = default;
        ServerFileManager(ServerFileManager const&) = delete;
        void operator=(ServerFileManager const&) = delete;

        virtual std::vector<FilePtr> const getServerFiles(const Index &idx) = 0;
        virtual ServerFilePtr const getAsParentDirFile(const std::string &filePath, const ServerFileContextPtr &context) = 0;

        virtual void adjustServerFilesForDirLayout(std::vector<FilePtr> &indexFiles, TimePoint &snapshot, uint8_t timestampMode) = 0;

        uint64_t getNewId();

    protected:
        ServerFileManager() = default;

        // inner map: filename/filePath - FilePtr
        std::map<ServerFileTree, std::map<std::string, ServerFilePtr>> serverFiles;

        uint64_t idCounter = 0;
    };
}

#endif //PCAPFS_VIRTUAL_FILES_SERVER_FILE_MANAGER_H
