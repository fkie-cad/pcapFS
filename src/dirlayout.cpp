#include "dirlayout.h"

#include <string>
#include <vector>
#include <numeric>
#include <boost/algorithm/string/split.hpp>

#include "offsets.h"
#include "logging.h"
#include "virtualfiles/smb/smb_manager.h"


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

    pcapfs_filesystem::DirTreeNode *
    DirectoryLayout::getOrCreateSubdirForServerFile(DirTreeNode *current, const pcapfs::ServerFilePtr &serverFile) {
        const std::string dirname = serverFile->getFilename();
        if (current->subdirs.count(dirname)) {
            current = current->subdirs.at(dirname);
        } else {
            DirTreeNode *parent_backup = current;
            current->subdirs[dirname] = new DirTreeNode;
            current = current->subdirs.at(dirname);
            current->dirname = dirname;
            current->accessTime = serverFile->getAccessTime();
            current->changeTime = serverFile->getChangeTime();
            current->modifyTime = serverFile->getModifyTime();
            current->parent = parent_backup;
        }
        return current;

    }


    void DirectoryLayout::initRoot() {
        ROOT = new DirTreeNode;
        ROOT->parent = nullptr;
        ROOT->dirname = "/";
    }


    DirTreeNode* DirectoryLayout::handleServerFile(DirTreeNode *current, pcapfs::ServerFilePtr &serverFilePtr, std::vector<pcapfs::ServerFilePtr> &parentDirs) {
        // advance all the way to parent dir of server file and create new tree nodes on the fly if necessary
        current = std::accumulate(parentDirs.begin(), parentDirs.end(), current, [](DirTreeNode* curr, const auto &parentDirFile )
                                    { return getOrCreateSubdirForServerFile(curr, parentDirFile); });

        if (serverFilePtr->isDirectory && current->subdirs.count(serverFilePtr->getFilename()) == 0) {
            // serverfile is a directory. Add it as new DirTreeNode if not already present in subdirs of current node
            current = getOrCreateSubdirForServerFile(current, serverFilePtr);
            LOG_TRACE << "added server file " << serverFilePtr->getFilename() << " as directory to tree node " << current->dirname;
        } else if (!serverFilePtr->isDirectory) {
            // add server file as regular file
            current->dirfiles.emplace(serverFilePtr->getFilename(), serverFilePtr);
            LOG_TRACE << "added server file " << serverFilePtr->getFilename() << " to DirTreeNode " << current->dirname;
        }

        // update timestamps for serverfile dirs
        if (!parentDirs.empty()) {
            const std::string rootDirName = parentDirs.front()->getFilename();
            if (current->accessTime < serverFilePtr->getAccessTime()) {
                current->accessTime = serverFilePtr->getAccessTime();
                DirTreeNode *temp = current;
                while (temp != ROOT) {
                    if (temp->parent->accessTime < temp->accessTime) {
                        temp->parent->accessTime = temp->accessTime;
                        if (temp->parent->dirname == rootDirName)
                            break;
                        temp = temp->parent;
                    } else {
                        break;
                    }
                }
            }
            if (current->modifyTime < serverFilePtr->getModifyTime()) {
                current->modifyTime = serverFilePtr->getModifyTime();
                DirTreeNode *temp = current;
                while (temp != ROOT) {
                    if (temp->parent->modifyTime < temp->modifyTime) {
                        temp->parent->modifyTime = temp->modifyTime;
                        if (temp->parent->dirname == rootDirName)
                            break;
                        temp = temp->parent;
                    } else {
                        break;
                    }
                }
            }
            if (current->changeTime < serverFilePtr->getChangeTime()) {
                current->changeTime = serverFilePtr->getChangeTime();
                DirTreeNode *temp = current;
                while (temp != ROOT) {
                    if (temp->parent->changeTime < temp->changeTime) {
                        temp->parent->changeTime = temp->changeTime;
                        if (temp->parent->dirname == rootDirName)
                            break;
                        temp = temp->parent;
                    } else {
                        break;
                    }
                }
            }
        }

        return current;
    }


    int DirectoryLayout::fillDirTreeSortby(const pcapfs::Index &index, const pcapfs::TimePoint &snapshot) {
        initRoot();
        auto files = index.getFiles();
        pcapfs::smb::SmbManager::getInstance().adjustSmbFilesForDirLayout(files, snapshot);

        bool earlyBreak = false;

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
                    const std::string property = file->getProperty(category);
                    LOG_TRACE << category << " and creating dir for " << file->getProperty(category);
                    if (property == "") {
                        current = getOrCreateSubdir(current, "PCAPFS_PROP_NOT_AVAIL");

                    } else if (file->flags.test(pcapfs::flags::IS_SERVERFILE) && category == "srcIP") {
                        pcapfs::ServerFilePtr serverFilePtr = std::static_pointer_cast<pcapfs::ServerFile>(file);
                        std::vector<pcapfs::ServerFilePtr> parentDirs = serverFilePtr->getAllParentDirs();

                        // we need to branch out of directory hierarchy and add the file to all folders corresponding to the clientIPs
                        std::set<std::string> ips = serverFilePtr->getClientIPs();
                        for (const auto &ip: ips) {
                            DirTreeNode *temp = current;
                            temp = getOrCreateSubdir(temp, ip);
                            // create subdirs for following properties
                            for (auto pos = std::find(dirSortby.begin(), dirSortby.end(), category) + 1; pos != dirSortby.end(); ++pos) {
                                std::string tmpProp = file->getProperty(*pos);
                                if (tmpProp == "")
                                    tmpProp = "PCAPFS_PROP_NOT_AVAIL";
                                temp = getOrCreateSubdir(temp, tmpProp);
                            }

                            temp = handleServerFile(temp, serverFilePtr, parentDirs);
                        }
                        earlyBreak = true;
                        break;

                    } else {
                        current = getOrCreateSubdir(current, property);
                    }
                }
            }

            if (earlyBreak) {
                earlyBreak = false;
                continue;
            }

            if (file->flags.test(pcapfs::flags::IS_SERVERFILE)) {
                pcapfs::ServerFilePtr serverFilePtr = std::static_pointer_cast<pcapfs::ServerFile>(file);
                std::vector<pcapfs::ServerFilePtr> parentDirs = serverFilePtr->getAllParentDirs();
                current = handleServerFile(current, serverFilePtr, parentDirs);
            } else {
                //TODO: implement new map for mapping from file path -> IndexPosition
                current->dirfiles.emplace(file->getFilename(), file);

                if (current->accessTime < file->getTimestamp()) {
                    current->accessTime = file->getTimestamp();
                    current->modifyTime = file->getTimestamp();
                    DirTreeNode *temp = current;
                    while (temp != ROOT) {
                        if (temp->parent->accessTime < temp->accessTime) {
                            temp->parent->modifyTime = temp->modifyTime;
                            temp->parent->accessTime = temp->accessTime;
                            temp = temp->parent;
                        } else {
                            break;
                        }
                    }
                }
                if (current->changeTime > file->getTimestamp()) {
                    current->changeTime = file->getTimestamp();
                    DirTreeNode *temp = current;
                    while (temp != ROOT) {
                        if (temp->parent->changeTime > temp->changeTime) {
                            temp->parent->changeTime = temp->changeTime;
                            temp = temp->parent;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        return 0;
    }


    int DirectoryLayout::initFilesystem(const pcapfs::Index &index, const std::string &sortby, const pcapfs::TimePoint &snapshot) {
        dirSortby = pathVector(sortby);
        fillDirTreeSortby(index, snapshot);
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
