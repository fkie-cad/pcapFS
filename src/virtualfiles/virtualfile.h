#ifndef PCAPFS_VIRTUAL_FILES_VIRTUALFILE_H
#define PCAPFS_VIRTUAL_FILES_VIRTUALFILE_H

#include <bitset>
#include <string>
#include <vector>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>

#include "../commontypes.h"
#include "../file.h"
#include "../offsets.h"


namespace pcapfs {

    class VirtualFile : public File {
    public:
    	/*
    	 * TODO:
    	 * Maybe we should change this signature.
    	 * char *buf should be a vecotr or Bytes type. The read function itself should convert it to vector.data().
    	 * Then we do not run into the length issue anymore like with the HMAC size in SslFile read().
    	 */
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override = 0;

        bool showFile() override;

        std::string getOffsetType() { return offsetType; }

        void setOffsetType(const std::string &filetype) { this->offsetType = filetype; };

        void setFirstPacketNumber(uint64_t x) { firstPacketNumber = x; };

        std::string getFilename() override;

        //TODO: get iterator for offsets?
        std::vector<SimpleOffset> offsets;

        void serialize(boost::archive::text_oarchive &archive) override;

        void deserialize(boost::archive::text_iarchive &archive) override;

    protected:
        std::string offsetType;
        uint64_t firstPacketNumber;
    };


    typedef std::shared_ptr<VirtualFile> VirtualFilePtr;

}

#endif //#define PCAPFS_VIRTUAL_FILES_VIRTUALFILE_H

