#include <chrono>

#include "file.h"

#include "logging.h"


pcapfs::File::File() : filesizeRaw(0), filesizeProcessed(0), idInIndex(0) {}


std::string pcapfs::File::getProperty(const std::string &property) {
    return properties[property];
}


void pcapfs::File::setProperty(const std::string &a, const std::string &b) {
    properties[a] = b;
}

/*
 * Is called by every file.
 * We need to handle SSL differently (because of the Decryption step we need to apply).
 * If the buffer is resized before the read function, the buffer is never empty.
 * Therefore, we exclude the buffer.resize operation for SSL Files.
 * If an SSLFile reads the first time, the buffer is empty.
 * It can check the buffer and if it is empty, it does one large encryption.
 * If not, we continue as the buffer is already filled with the plaintext.
 */
void pcapfs::File::fillBuffer(const Index &idx) {

	bool breakpoint = false;
	if(this->filetype == "ssl") {
		breakpoint = true;
	}

	if(filesizeProcessed == 0 || !flags.test(pcapfs::flags::SSL_SIZE_CALCULATED)) {
		LOG_ERROR << "This should not be called, set filesizeProcessed at the proper position! (" << this->filetype << ")";
		LOG_TRACE << "current buffer size: " << buffer.size();

		buffer.resize(filesizeRaw);

		read(0, filesizeRaw, idx, (char *) buffer.data());
		LOG_TRACE << "new filesizeRaw: " << filesizeRaw;
	} else {
		// filesizeProcessed can be used as the file has been processed:
		LOG_TRACE << "current buffer size: " << buffer.size();
		buffer.resize(filesizeProcessed);
		read(0, filesizeProcessed, idx, (char *) buffer.data());
		LOG_TRACE << "new filesizeProcessed: " << filesizeProcessed;
	}
}


pcapfs::Bytes pcapfs::File::getBuffer() {
    if (buffer.empty()) {
        LOG_ERROR << "Reading empty buffer of file " << filename;
        throw;
    } else {
        return buffer;
    }
}


void pcapfs::File::clearBuffer() {
    buffer.clear();
}


uint64_t pcapfs::File::getFilesizeProcessed() {
    if (flags.test(pcapfs::flags::SSL_SIZE_CALCULATED)) {
        return filesizeProcessed;
    } else {
        return filesizeRaw;
    }
}


bool pcapfs::File::meetsDecodeMapCriteria(const std::string &file) {
    for (const auto &entries : config.getDecodeMapFor(file)) {
        for (const auto &it : entries) {
            if (this->getProperty(it.first) != it.second) {
                return false;
            }
        }
        return true;
    }
    return false;
}

 std::string pcapfs::File::to_string() {

	 std::stringstream ss;

	 ss << "File(\n"
    			<< "  filetype: " << this->getFiletype() << "\n"
				<< "  filename: " << this->getFilename() << "\n"
				<< "  filesizeRaw: " << this->getFilesizeRaw() << "\n"
				<< "  filesizeProcessed: " << this->getFilesizeProcessed() << "\n"
				<< "  buffer: " << this->getBuffer().data() << "\n"
				<< ")";

	 std::string ret = ss.str();

	 return ret;

}

void pcapfs::File::serialize(boost::archive::text_oarchive &archive) {
    //uint16_t
    archive << filetype;
    //std::string
    archive << filename;
    //time_point
    archive << boost::serialization::make_binary_object(&timestamp, sizeof(timestamp));;
    //uint64_t
    archive << filesizeRaw;
    //uint64_t
    archive << filesizeProcessed;
    //uint64_t
    archive << idInIndex;
    //std::map<std::string, std::string>
    archive << properties;
    //std::bitset
    archive << flags;
}


void pcapfs::File::deserialize(boost::archive::text_iarchive &archive) {
    //file type is handled before
    //std::string
    archive >> filename;
    //time_point
//    std::chrono::system_clock::duration d;
//    archive >> d;
//    timestamp = std::chrono::system_clock::time_point(d);
    archive >> boost::serialization::make_binary_object(&timestamp, sizeof(timestamp));;
    //uint64_t
    archive >> filesizeRaw;
    //uint64_t
    archive >> filesizeProcessed;
    //uint64_t
    archive >> idInIndex;
    //std::map<std::string, std::string>
    archive >> properties;
    //std::bitset
    archive >> flags;
}

pcapfs::options::PcapFsOptions pcapfs::File::config = pcapfs::options::PcapFsOptions{};

//TODO: destructor!
