#ifndef PCAPFS_FILESYSTEM_H
#define PCAPFS_FILESYSTEM_H

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "index.h"
#include "commontypes.h"
#include "virtualfiles/serverfile.h"


namespace pcapfs_filesystem {

    typedef std::map<std::string, pcapfs::FilePtr> FileIndexMap;

    typedef struct DirTreeNode {
        std::string dirname;
        DirTreeNode *parent;
        std::map<std::string, struct DirTreeNode *> subdirs;
        FileIndexMap dirfiles;
        pcapfs::TimePoint accessTime = pcapfs::TimePoint::min();
        pcapfs::TimePoint changeTime = pcapfs::TimePoint::max();
        pcapfs::TimePoint modifyTime = pcapfs::TimePoint::min();
    } DirTreeNode;


    extern pcapfs::Index index;


    class DirectoryLayout {
    public:
        static int initFilesystem(const pcapfs::Index &index, const std::string &sortby, const pcapfs::TimePoint &snapshot);

        static DirTreeNode *findDirectory(const std::vector<std::string> &path_v);

        static pcapfs::FilePtr findFile(const std::string &path);

        static std::vector<std::string> pathVector(std::string path);

    private:
        static DirTreeNode *ROOT;
        static std::vector<std::string> dirSortby;

        static DirTreeNode *handleServerFile(DirTreeNode *current, pcapfs::ServerFilePtr &serverFilePtr, std::vector<pcapfs::ServerFilePtr> &parentDirs);

        static int fillDirTreeSortby(const pcapfs::Index &index, const pcapfs::TimePoint &snapshot);

        static DirTreeNode *getOrCreateSubdir(DirTreeNode *current, const std::string &dirname);
        static DirTreeNode *getOrCreateSubdirForServerFile(DirTreeNode *current, const pcapfs::ServerFilePtr &serverFile);

        static void initRoot();

    };

}

#endif //PCAPFS_FILESYSTEM_H
