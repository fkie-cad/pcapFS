#include "dirlayout.h"

#include <string>
#include <vector>
#include <numeric>

#include <boost/algorithm/string/split.hpp>

#include "offsets.h"
#include "logging.h"


namespace pcapfs_filesystem {

    pcapfs_filesystem::DirTreeNode *DirectoryLayout::ROOT = nullptr;
    std::vector<std::string> DirectoryLayout::dirSortby;
    pcapfs::Index index;


    pcapfs_filesystem::DirTreeNode *DirectoryLayout::findDirectory(const std::vector<std::string> &path_v) {
        DirTreeNode *current = ROOT;
        try {
            for (const std::string &dirname: path_v) {
                current = current->subdirs.at(dirname);
            }
            return current;
        }
        catch (std::out_of_range &x) {
            LOG_INFO << "Directory " << path_v.back() << " requested but not found";
            return nullptr;
        }
    }


    pcapfs::FilePtr DirectoryLayout::findFile(const std::string &path) {
        std::vector<std::string> path_v = pathVector(path);
        std::string filename = path_v.back();
        path_v.pop_back();
        DirTreeNode *dir = findDirectory(path_v);
        if (dir == nullptr) {
            return nullptr;
        }

        if (dir->dirfiles.count(filename) < 1) {
            return nullptr;
        }
        pcapfs::FilePtr file = dir->dirfiles.at(filename);
        if (!file->showFile()) {
            return nullptr;
        }
        return file;
    }


    pcapfs_filesystem::DirTreeNode *
    DirectoryLayout::getOrCreateSubdir(DirTreeNode *current, const std::string &dirname) {
        if (current->subdirs.count(dirname)) {
            current = current->subdirs.at(dirname);
        } else {
            DirTreeNode *parent_backup = current;
            current->subdirs[dirname] = new DirTreeNode;
            current = current->subdirs.at(dirname);
            current->dirname = dirname;
            current->parent = parent_backup;
        }
        return current;
    }


    void DirectoryLayout::initRoot() {
        ROOT = new DirTreeNode;
        ROOT->parent = nullptr;
        ROOT->dirname = "/";
    }


    int DirectoryLayout::fillDirTreeSortby(const pcapfs::Index &index) {
        initRoot();
        auto files = index.getFiles();

        for (auto &file : files) {
            if (!file->showFile()) {
                continue;
            }

            bool f_is_http = file->isFiletype("http");
            DirTreeNode *current = ROOT;
            for (const std::string &category: dirSortby) {
                if (category == "path") {
                    if (!f_is_http) {
                        continue;
                    }
                    // "-" added to filename to avoid empty string after "/",
                    // no side-effect, because last vector element is popped anyway
                    std::vector<std::string> path_v = pathVector(file->getProperty("uri") + "-");
                    if (file->getProperty("uri") != "")
                        path_v.pop_back();
                    if (path_v.empty()) {
                        continue;
                    }
                    current = std::accumulate(path_v.begin(), path_v.end(), current,
                                                [](DirTreeNode* curr, const std::string &dir ){ return getOrCreateSubdir(curr, dir); });
                } else {
                    std::string property = file->getProperty(category);
                    LOG_TRACE << category << " and creating dir for " << file->getProperty(category);
                    if (property == "") {
                        current = getOrCreateSubdir(current, "PCAPFS_PROP_NOT_AVAIL");
                    } else {
                        current = getOrCreateSubdir(current, property);
                    }
                }
            }
            //TODO: implement new map for mapping from file path -> IndexPosition
            current->dirfiles.emplace(file->getFilename(), file);

            //TODO: does this make sense?
            DirTreeNode *temp = current;
            if (current->timestamp < file->getTimestamp()) {
                current->timestamp = file->getTimestamp();
                while (temp != ROOT) {
                    if (temp->parent->timestamp < temp->timestamp) {
                        temp->parent->timestamp = temp->timestamp;
                        temp = temp->parent;
                    } else {
                        break;
                    }
                }
            }
            if (current->timestampOldest > file->getTimestamp()) {
                current->timestampOldest = file->getTimestamp();
                while (temp != ROOT) {
                    if (temp->parent->timestamp > temp->timestamp) {
                        temp->parent->timestampOldest = temp->timestampOldest;
                        temp = temp->parent;
                    } else {
                        break;
                    }
                }
            }
        }
        return 0;
    }


    int DirectoryLayout::initFilesystem(const pcapfs::Index &index, const std::string &sortby) {
        dirSortby = pathVector(sortby);
        fillDirTreeSortby(index);
        pcapfs_filesystem::index = index;
        return 0;
    }


    std::vector<std::string> DirectoryLayout::pathVector(std::string path) {
        std::vector<std::string> split;
        boost::split(split, path, [](char c) { return c == '/'; });
        //remove empty strings in vector
        split.erase(remove_if(split.begin(), split.end(), [&](const std::string &x) -> bool { return x.empty(); }),
                       split.end());

        return split;
    }

}
