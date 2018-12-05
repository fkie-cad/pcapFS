#ifndef PCAPFS_PCAPFS_H
#define PCAPFS_PCAPFS_H

#include "fuse.h"
#include "index.h"
#include "dirlayout.h"


namespace pcapfs {


    class PcapFs : public Fusepp::Fuse<PcapFs> {
    public:

        PcapFs() = delete;

        explicit PcapFs(pcapfs::Index &idx);

        static int getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);

        static int read(const char *path, char *buf, size_t size, off_t start_offset, struct fuse_file_info *fi);

        static int open(const char *path, struct fuse_file_info *fi);

        static int readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi,
                           enum fuse_readdir_flags flags);

        pcapfs::Index &index;

    };

}

#endif //PCAPFS_PCAPFS_H
