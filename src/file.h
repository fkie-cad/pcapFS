#ifndef PCAPFS_FILE_H
#define PCAPFS_FILE_H

#include <chrono>
#include <map>
#include <memory>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/binary_object.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>

#include "commontypes.h"
#include "properties.h"
#include "config.h"
#include "index.h"


namespace pcapfs {
    namespace flags {
        const unsigned char IS_METADATA = 0; // 0000 0001
        const unsigned char COMPRESSED_GZIP = 1; // 0000 0010
        const unsigned char COMPRESSED_DEFLATE = 2; // 0000 0100
        const unsigned char CHUNKED = 3; // 0000 1000
        const unsigned char IS_REAL_FILE = 4; // 0001 0000
        const unsigned char PROCESSED = 5; // 0010 0000
        const unsigned char IS_SERVERFILE = 6; // 0100 0000
        const unsigned char MISSING_DATA = 7; // 1000 0000
        const unsigned char HAS_DECRYPTION_KEY = 8;
        const unsigned char PARSED = 9;
        const unsigned char IS_EMBEDDED_FILE = 10;
        const unsigned char CS_DO_NOT_SHOW = 11;
    }

    struct Fragment {
        uint64_t id = 0L;
        uint64_t start = 0L;
        uint64_t length = 0L;

        template<class Archive>
        void serialize(Archive &archive, const unsigned int) {
            archive & id;
            archive & start;
            archive & length;
        }
    };


    typedef std::pair<uint64_t, TimePoint> FragmentWithTime;

    class Index;

    class File {
        friend class Index;

    public:

        File() : filesizeRaw(0), filesizeProcessed(0), idInIndex(0) {};

        virtual ~File() = default;

        virtual size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) = 0;

        virtual bool showFile() = 0;

        virtual std::string getFilename() { return filename; };

        std::string getFiletype() const { return filetype; };

        TimePoint getTimestamp() { return timestamp; };

        uint64_t getFilesizeRaw() { return filesizeRaw; };

        uint64_t getFilesizeProcessed();

        uint64_t getIdInIndex() { return idInIndex; };

        Bytes getBuffer();

        void fillBuffer(const Index &idx);

        void clearBuffer();

        void setFilename(const std::string &filename) { this->filename = filename; };

        void setFiletype(const std::string &filetype) { this->filetype = filetype; };

        void setFilesizeRaw(uint64_t filesizeRaw) { this->filesizeRaw = filesizeRaw; };

        void setFilesizeProcessed(uint64_t filesizeProcessed) { this->filesizeProcessed = filesizeProcessed; };

        void setTimestamp(TimePoint timestamp) { this->timestamp = timestamp; };

        void setIdInIndex(uint64_t id) { this->idInIndex = id; };

        bool isFiletype(const std::string &filetype) { return (this->filetype == filetype); };

        void setProperty(const std::string &a, const std::string &b);

        std::string getProperty(const std::string &property);

        static void setConfig(const options::PcapFsOptions &config_) { config = config_; };

        bool meetsDecodeMapCriteria(const std::string &file);

        std::bitset<12> flags;

        std::vector<FragmentWithTime> connectionBreaks; //TODO: are they good here?


        virtual void serialize(boost::archive::text_oarchive &archive);

        virtual void deserialize(boost::archive::text_iarchive &archive);

        std::string to_string();


    protected:
        std::string filetype;
        std::string filename;
        TimePoint timestamp;
        uint64_t filesizeRaw = 0L;
        uint64_t filesizeProcessed = 0L;
        uint64_t idInIndex = 0L;
        std::map<std::string, std::string> properties;

        static options::PcapFsOptions config;

        Bytes buffer;
    };

    typedef std::shared_ptr<File> FilePtr;
}

#endif //PCAPFS_FILE_H
