#include <chrono>

#include "pcapfs.h"

#include "dirlayout.h"


pcapfs::PcapFs::PcapFs(pcapfs::Index &idx) : index(idx) {}


int pcapfs::PcapFs::getattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
    std::vector<std::string> path_v = pcapfs_filesystem::DirectoryLayout::pathVector(path);
    memset(stbuf, 0, sizeof(struct stat));

    pcapfs_filesystem::DirTreeNode *node = pcapfs_filesystem::DirectoryLayout::findDirectory(path_v);
    if (node != nullptr) {
        stbuf->st_mode = S_IFDIR | 0444;
        stbuf->st_nlink = 2;
        stbuf->st_size = node->dirfiles.size();
        stbuf->st_mtim = {std::chrono::system_clock::to_time_t(node->timestamp), 0};
        stbuf->st_atim = {std::chrono::system_clock::to_time_t(node->timestamp), 0};
        stbuf->st_ctim = {std::chrono::system_clock::to_time_t(node->timestampOldest), 0};

    } else {
        pcapfs::FilePtr f_p = pcapfs_filesystem::DirectoryLayout::findFile(path);
        if (f_p == nullptr) {
            return -ENOENT;
        }
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_mtim = {std::chrono::system_clock::to_time_t(f_p->getTimestamp()), 0};
        stbuf->st_atim = {std::chrono::system_clock::to_time_t(f_p->getTimestamp()), 0};
        stbuf->st_ctim = {std::chrono::system_clock::to_time_t(f_p->getTimestamp()), 0};

        //TODO: create flag for "use processed size"
        if (f_p->flags.test(pcapfs::flags::PROCESSED)) {
            stbuf->st_size = f_p->getFilesizeProcessed();
        } else {
            stbuf->st_size = f_p->getFilesizeRaw();
        }
    }
    return 0;
}


int pcapfs::PcapFs::read(const char *path, char *buf, size_t size, off_t start_offset, struct fuse_file_info *) {
    pcapfs::FilePtr f_p = pcapfs_filesystem::DirectoryLayout::findFile(path);
    if (f_p == nullptr) {
        return -ENOENT;
    }
    LOG_TRACE << "reading from" << path << " size: " << size << "start_offset: " << start_offset;
    return f_p->read(start_offset, size, pcapfs_filesystem::index, buf);
}


int pcapfs::PcapFs::open(const char *path, struct fuse_file_info *) {
    if (pcapfs_filesystem::DirectoryLayout::findFile(path) == nullptr) {
        return -ENOENT;
    }
    return 0;
}


int pcapfs::PcapFs::readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *,
                            enum fuse_readdir_flags) {
    // TODO update to new dir_tree structure
    if (offset < 1) {
        if (0 != filler(buf, ".", nullptr, 1, (fuse_fill_dir_flags) 0))
            return 0;
    }
    if (offset < 2) {
        if (0 != filler(buf, "..", nullptr, 2, (fuse_fill_dir_flags) 0))
            return 0;
    }
    int cnt = 2;
    std::vector<std::string> path_v = pcapfs_filesystem::DirectoryLayout::pathVector(path);
    pcapfs_filesystem::DirTreeNode *dir = pcapfs_filesystem::DirectoryLayout::findDirectory(path_v);
    LOG_TRACE << "Directory depth: " << path_v.size();
    // List directories
    for (const auto &map_it : dir->subdirs) {
        pcapfs_filesystem::DirTreeNode *subdir = map_it.second;
        if (offset > cnt++) continue;
        if (0 != filler(buf, subdir->dirname.c_str(), nullptr, cnt, (fuse_fill_dir_flags) 0)) {
            return 0;
        }
    }
    LOG_TRACE << "Readdir lists " << cnt - 2 << " dirs in " << path;
    // List files in dir
    for (const auto &map_it : dir->dirfiles) {
        const pcapfs::FilePtr file = map_it.second;

        if (offset > cnt++) continue;
        if (file->getFilename().size() > 255) {
            LOG_ERROR << "Filename (" << file->getFilename() << ") too long!";
        }
        if (0 != filler(buf, file->getFilename().c_str(), nullptr, cnt, (fuse_fill_dir_flags) 0)) {
            return 0;
        }
    }
    LOG_TRACE << "Readdir lists " << cnt - 2 << " entries in " << path;
    return 0;
}
