#include "http.h"

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/RawPacket.h>
#include <zlib.h>

#include "../filefactory.h"
#include "../logging.h"
#include "../cobaltstrike.h"

/*
 * HTTP Parsing function.
 * Is always called for a file that is classified as HTTP.
 */
std::vector<pcapfs::FilePtr> pcapfs::HttpFile::parse(pcapfs::FilePtr filePtr, pcapfs::Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    if(!isHttpTraffic(data)){
        return resultVector;
    }

    pcapfs::Configuration options;
    auto config = options.pcapfsOptions;

    size_t size = 0;
    headerMap header;
    std::string requestedFilename;
    std::string requestedHost;
    std::string requestedUri;
    bool prevWasRequest = false;
    size_t numElements = filePtr->connectionBreaks.size();

    LOG_TRACE << "HTTP parser, number of elements (connection breaks): " << numElements;

    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t &offset = filePtr->connectionBreaks.at(i).first;
        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        Fragment fragment;
        Fragment fragmentHeader;
        fragment.id = filePtr->getIdInIndex();
        fragmentHeader.id = filePtr->getIdInIndex();

        std::shared_ptr<HttpFile> resultPtr = std::make_shared<HttpFile>();
        std::shared_ptr<HttpFile> resultHeaderPtr = std::make_shared<HttpFile>();

        if (!prevWasRequest) {
            requestedFilename = "";
            requestedHost = "";
            requestedUri = "";
        }

        //TODO: create smaller functions for this big function!!
        if (isHTTPRequest(data, offset, size)) {
            size_t firstLine = getRequestLineLength(data, offset, size);
            size_t headerLength = parseHeaderFields(data, header, offset + firstLine, size - firstLine);
            if (headerLength == 0) {
                continue;
            }
            prevWasRequest = true;

            //create header of http request
            fragmentHeader.start = offset;
            fragmentHeader.length = firstLine + headerLength;
            resultHeaderPtr->fragments.push_back(fragmentHeader);
            resultHeaderPtr->setOffsetType(filePtr->getFiletype());

            resultHeaderPtr->setFilesizeRaw(fragmentHeader.length);
            resultHeaderPtr->setFilesizeProcessed(resultHeaderPtr->getFilesizeRaw());

            resultHeaderPtr->setFiletype("http");
            requestedHost = header["host"];

            requestedUri = getRequestUri(data, offset, size);
            requestedFilename = requestedHost + requestedUri;
            requestedFilename = uriToFilename(requestedFilename);

            LOG_TRACE << "requestedFilename: " << requestedFilename
            		<< " - requestedHost: " << requestedHost
        			<< " - requestedUri: " << requestedUri;

            LOG_TRACE << "fileSizeRaw: " << fragmentHeader.length;

            resultHeaderPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);

            const std::string requestMethod = requestMethodToString(getRequestMethod(data, offset, size));

            if (requestMethod == "GET" && header.find("cookie") != header.end()) {
                CobaltStrike::getInstance().handleHttpGet(header["cookie"], filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"));
            }

            if (requestedFilename != "") {
                resultHeaderPtr->setFilename(requestMethod + "-" + requestedFilename);
            } else {
                resultHeaderPtr->setFilename(requestMethod);
            }

            resultHeaderPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
            resultHeaderPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
            resultHeaderPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
            resultHeaderPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
            resultHeaderPtr->setProperty("domain", requestedHost);
            resultHeaderPtr->setProperty("uri", requestedUri);
            resultHeaderPtr->setProperty("protocol", "http");
            resultHeaderPtr->flags.set(pcapfs::flags::IS_METADATA);
            if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                resultHeaderPtr->flags.set(pcapfs::flags::MISSING_DATA);
                LOG_DEBUG << "HTTP missing data.";
            }
            resultVector.push_back(resultHeaderPtr);

            LOG_TRACE << "size: " << size << " - firstLine: " << firstLine << " - headerLength: " << headerLength;

            long diff = size - firstLine - headerLength;
            if (diff <= 0) {
                continue;
            }

            //create http request body
            fragment.start = offset + firstLine + headerLength;
            fragment.length = size - firstLine - headerLength;

            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);

            resultPtr->setOffsetType(filePtr->getFiletype());
            resultPtr->setFiletype("http");
            if (requestedFilename != "") {
                resultPtr->setFilename(requestMethod + "-" + requestedFilename);
            } else {
                resultPtr->setFilename(requestMethod);
            }
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
            resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
            resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
            resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);
            resultPtr->setProperty("protocol", "http");
            //TODO: add compression here
            if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
            }

            if (requestMethod == "POST" && CobaltStrike::getInstance().isKnownConnection(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"))) {
                resultPtr->flags.set(pcapfs::flags::COBALT_STRIKE);
                CobaltStrikeConnectionPtr connData = CobaltStrike::getInstance().getConnectionData(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"));
                if (connData)
                    resultPtr->cobaltStrikeKey = connData->aesKey;
                resultPtr->fromClient = true;
                resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSizeCS(idx, true));
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            } else {
                resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());
            }

            resultVector.push_back(resultPtr);
        } else if (isHTTPResponse(data, offset, size)) {
            size_t firstLine = getResponseLineLength(data, offset, size);
            size_t headerLength = parseHeaderFields(data, header, offset + firstLine, size - firstLine);
            if (headerLength == 0) {
                continue;
            }

            //create header of http response
            fragmentHeader.start = offset;
            fragmentHeader.length = firstLine + headerLength;
            resultHeaderPtr->fragments.push_back(fragmentHeader);
            resultHeaderPtr->setOffsetType(filePtr->getFiletype());

            resultHeaderPtr->setFilesizeRaw(fragmentHeader.length);
            resultHeaderPtr->setFilesizeProcessed(resultHeaderPtr->getFilesizeRaw());

            resultHeaderPtr->setFiletype("http");
            resultHeaderPtr->setFilename(requestedFilename);
            resultHeaderPtr->setProperty("srcIP", filePtr->getProperty("dstIP"));
            resultHeaderPtr->setProperty("dstIP", filePtr->getProperty("srcIP"));
            resultHeaderPtr->setProperty("srcPort", filePtr->getProperty("dstPort"));
            resultHeaderPtr->setProperty("dstPort", filePtr->getProperty("srcPort"));
            resultHeaderPtr->setProperty("domain", requestedHost);
            resultHeaderPtr->setProperty("uri", requestedUri);
            resultHeaderPtr->setProperty("protocol", "http");
            resultHeaderPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultHeaderPtr->flags.set(pcapfs::flags::IS_METADATA);
            if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                resultHeaderPtr->flags.set(pcapfs::flags::MISSING_DATA);
            }
            resultVector.push_back(resultHeaderPtr);

            long diff = size - firstLine - headerLength;
            if (diff <= 0) {
                continue;
            }

            //create http response body
            fragment.start = offset + firstLine + headerLength;
            fragment.length = size - firstLine - headerLength;

            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());

            resultPtr->setOffsetType(filePtr->getFiletype());
            resultPtr->setFiletype("http");
            resultPtr->setFilename(requestedFilename);
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->setProperty("srcIP", filePtr->getProperty("dstIP"));
            resultPtr->setProperty("dstIP", filePtr->getProperty("srcIP"));
            resultPtr->setProperty("srcPort", filePtr->getProperty("dstPort"));
            resultPtr->setProperty("dstPort", filePtr->getProperty("srcPort"));
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);
            resultPtr->setProperty("protocol", "http");
            if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
            }

            if (header["transfer-encoding"] == "chunked") {
                resultPtr->flags.set(pcapfs::flags::CHUNKED);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }
            if (header["content-encoding"] == "gzip") {
                resultPtr->flags.set(pcapfs::flags::COMPRESSED_GZIP);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }
            if (header["content-encoding"] == "deflate") {
                resultPtr->flags.set(pcapfs::flags::COMPRESSED_DEFLATE);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }

            if (CobaltStrike::getInstance().isKnownConnection(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"))) {
                resultPtr->flags.set(pcapfs::flags::COBALT_STRIKE);
                CobaltStrikeConnectionPtr connData = CobaltStrike::getInstance().getConnectionData(filePtr->getProperty("dstIP"), filePtr->getProperty("dstPort"));
                if (connData)
                    resultPtr->cobaltStrikeKey = connData->aesKey;
                resultPtr->fromClient = false;

                for (uint64_t index : resultPtr->checkEmbeddedCSFiles(idx)) {
                    std::shared_ptr<HttpFile> embeddedFilePtr = std::make_shared<HttpFile>();
                    Fragment embeddedFragment;
                    embeddedFragment.id = filePtr->getIdInIndex();
                    embeddedFragment.start = fragment.start;
                    embeddedFragment.length = fragment.length;

                    embeddedFilePtr->fragments.push_back(embeddedFragment);
                    embeddedFilePtr->setFilesizeRaw(embeddedFragment.length);
                    embeddedFilePtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());

                    embeddedFilePtr->csEmbeddedFileIndex = index;

                    embeddedFilePtr->setOffsetType(filePtr->getFiletype());
                    embeddedFilePtr->setFiletype("http");
                    embeddedFilePtr->setFilename(requestedFilename + "_embedded_file"+std::to_string(index));
                    embeddedFilePtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
                    embeddedFilePtr->setProperty("srcIP", filePtr->getProperty("dstIP"));
                    embeddedFilePtr->setProperty("dstIP", filePtr->getProperty("srcIP"));
                    embeddedFilePtr->setProperty("srcPort", filePtr->getProperty("dstPort"));
                    embeddedFilePtr->setProperty("dstPort", filePtr->getProperty("srcPort"));
                    embeddedFilePtr->setProperty("domain", requestedHost);
                    embeddedFilePtr->setProperty("uri", requestedUri);
                    embeddedFilePtr->setProperty("protocol", "http");
                    embeddedFilePtr->flags.set(pcapfs::flags::IS_EMBEDDED_FILE);
                    embeddedFilePtr->flags.set(pcapfs::flags::PROCESSED);
                    embeddedFilePtr->flags.set(pcapfs::flags::COBALT_STRIKE);

                    if (connData)
                        embeddedFilePtr->cobaltStrikeKey = connData->aesKey;
                    embeddedFilePtr->fromClient = false;
                    embeddedFilePtr->setFilesizeProcessed(embeddedFilePtr->calculateProcessedSizeCS(idx, false));

                    resultVector.push_back(embeddedFilePtr);
                }

                resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSizeCS(idx, false));
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            } else {
                resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));
            }

            LOG_TRACE << "calculateProcessedSize got: " << resultPtr->getFilesizeProcessed();
            if (resultPtr->getFilesizeProcessed() == 0) {
                continue;
            }
            prevWasRequest = false;

            resultVector.push_back(resultPtr);
        }  else if(prevWasRequest && config.allowHTTP09 == true) {

            if (size == 0) {
                continue;
            }

            //create http response body
            fragment.start = offset;
            fragment.length = size;

            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilesizeProcessed(resultPtr->getFilesizeRaw());

            resultPtr->setOffsetType(filePtr->getFiletype());
            resultPtr->setFiletype("http");
            resultPtr->setFilename(requestedFilename);
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->setProperty("srcIP", filePtr->getProperty("dstIP"));
            resultPtr->setProperty("dstIP", filePtr->getProperty("srcIP"));
            resultPtr->setProperty("srcPort", filePtr->getProperty("dstPort"));
            resultPtr->setProperty("dstPort", filePtr->getProperty("srcPort"));
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);
            resultPtr->setProperty("protocol", "http");
            if (filePtr->flags.test(pcapfs::flags::MISSING_DATA)) {
                resultPtr->flags.set(pcapfs::flags::MISSING_DATA);
            }

            if (header["transfer-encoding"] == "chunked") {
                resultPtr->flags.set(pcapfs::flags::CHUNKED);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }
            if (header["content-encoding"] == "gzip") {
                resultPtr->flags.set(pcapfs::flags::COMPRESSED_GZIP);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }
            if (header["content-encoding"] == "deflate") {
                resultPtr->flags.set(pcapfs::flags::COMPRESSED_DEFLATE);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
            }

            resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));

            LOG_TRACE << "calculateProcessedSize got: " << resultPtr->getFilesizeProcessed();
            if (resultPtr->getFilesizeProcessed() == 0) {
                continue;
            }
            prevWasRequest = false;

            resultVector.push_back(resultPtr);
        }
    }
    return resultVector;
}


std::vector<uint64_t> pcapfs::HttpFile::checkEmbeddedCSFiles(const Index &idx) {
    Bytes rawData, decryptedData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    return CobaltStrike::getInstance().extractEmbeddedFileInfos(rawData, cobaltStrikeKey);
}


int pcapfs::HttpFile::calculateProcessedSizeCS(const Index &idx, bool fromClient) {
    Bytes rawData, decryptedData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    if (flags.test(pcapfs::flags::IS_EMBEDDED_FILE))
        return CobaltStrike::getInstance().decryptEmbeddedFile(rawData, cobaltStrikeKey, csEmbeddedFileIndex).size();
    else
        return CobaltStrike::getInstance().decryptPayload(rawData, cobaltStrikeKey, fromClient).size();
}


size_t pcapfs::HttpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    if (flags.test(pcapfs::flags::COMPRESSED_GZIP)) {
        return readGzip(startOffset, length, idx, buf);
    } else if (flags.test(pcapfs::flags::COMPRESSED_DEFLATE)) {
        return readDeflate(startOffset, length, idx, buf);
    } else if (flags.test(pcapfs::flags::CHUNKED)) {
        return readChunked(startOffset, length, idx, buf);
    } else if (flags.test(pcapfs::flags::COBALT_STRIKE)) {
        return readCS(startOffset, length, idx, buf);
    } else {
        return readRaw(startOffset, length, idx, buf);
    }
}


int pcapfs::HttpFile::readCS(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));

    Bytes decryptedData;
    if (flags.test(pcapfs::flags::IS_EMBEDDED_FILE))
        decryptedData = CobaltStrike::getInstance().decryptEmbeddedFile(rawData, cobaltStrikeKey, csEmbeddedFileIndex);
    else
        decryptedData = CobaltStrike::getInstance().decryptPayload(rawData, cobaltStrikeKey, fromClient);
    memcpy(buf, decryptedData.data() + startOffset, length);
    return std::min(decryptedData.size() - startOffset, length);
}


int pcapfs::HttpFile::readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: right now this assumes each http file only contains ONE offset into a tcp stream
    Fragment fragment = fragments.at(0);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    //TODO: sanitizing length is done in filePtr->read!
    return filePtr->read(startOffset + fragment.start, length, idx, buf);
}


int pcapfs::HttpFile::readGzip(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData;
    rawData.resize(filesizeRaw + 1);
    uint64_t size;

    if (flags.test(pcapfs::flags::CHUNKED)) {
        size = readChunked(0, filesizeRaw, idx, (char *) rawData.data());
        rawData.resize(size);
    } else {
        readRaw(0, filesizeRaw, idx, (char *) rawData.data());
        size = filesizeRaw;
    }

    namespace bio = boost::iostreams;
    std::stringstream compressed;
    std::stringstream decompressed;
    compressed.write((char *) rawData.data(), size);

    bio::filtering_istreambuf out{};
    out.push(bio::gzip_decompressor());
    out.push(compressed);

    std::streamsize decr_size = 0;
    try {
        decr_size = bio::copy(out, decompressed);
    } catch (bio::gzip_error &e) {
        LOG_WARNING << "Gzip Error: " << e.what();
        //return read_compressed(file, pcapif, buf, size, start_offset);
    }

    int readCount = (int) std::min((size_t) decr_size - startOffset, length);
    if (readCount <= 0) {
        return 0;
    }

    if (buf == nullptr) {
        LOG_ERROR << "no buffer specified in readGzip!";
    }
    decompressed.seekg(startOffset);
    decompressed.read(buf, readCount);
    return readCount;
}


int pcapfs::HttpFile::calculateProcessedSize(const Index &idx) {
    Bytes data;
    data.resize(filesizeRaw);

    if (flags.test(pcapfs::flags::CHUNKED)) {
        int chunkedSize = readChunked(0, filesizeRaw, idx, (char *) data.data());
        if (chunkedSize == 0) {
            return 0;
        }
        data.resize(chunkedSize);
    } else {
        readRaw(0, filesizeRaw, idx, (char *) data.data());
    }

    /*
     * Flag for mac size could be inserted here
     */

    if (flags.test(pcapfs::flags::COMPRESSED_GZIP)) {
        namespace bio = boost::iostreams;

        std::stringstream compressed;
        std::stringstream decompressed;
        compressed.write((const char *) data.data(), data.size());

        bio::filtering_istreambuf out{};
        out.push(bio::gzip_decompressor());
        out.push(compressed);

        std::streamsize decr_size = 0;
        try {
            decr_size = bio::copy(out, decompressed);
        } catch (bio::gzip_error &e) {
            LOG_WARNING << "Gzip Error: " << e.what();
        }
        return decr_size;
    }

    if (flags.test(pcapfs::flags::COMPRESSED_DEFLATE)) {
        uInt inlen = static_cast<uInt>(data.size());
        uInt outlen = inlen * 5;
        Bytef *inflated = new Bytef[outlen];
        z_stream zs{};
        if (inflateInit2(&zs, MAX_WBITS) != Z_OK) {
            LOG_ERROR << "ZLIB init error";
            delete[] inflated;
            return 0;
        }

        zs.next_in = reinterpret_cast<Bytef *>((char *) data.data());
        zs.avail_in = inlen;
        zs.next_out = inflated;
        zs.avail_out = outlen;

        int zlib_return = inflate(&zs, Z_SYNC_FLUSH);
        while (zlib_return == Z_OK && zs.avail_out == 0) {
            zs.avail_out = outlen * 2;
            inflated = static_cast<Bytef *>(realloc(inflated, outlen * 3));
            zs.next_out = inflated + outlen;
            outlen *= 3;
            zlib_return = inflate(&zs, Z_SYNC_FLUSH);
        }
        if (zlib_return == Z_DATA_ERROR) {
            if (inflateReset2(&zs, -MAX_WBITS) != Z_OK) {
                LOG_ERROR << "ZLIB reset error";
                delete[] inflated;
                return 0;
            }

            zs.next_in = reinterpret_cast<Bytef *>((char *) data.data());
            zs.avail_in = inlen;
            zs.next_out = inflated;
            zs.avail_out = outlen;

            zlib_return = inflate(&zs, Z_SYNC_FLUSH);
            while (zlib_return == Z_OK && zs.avail_out == 0) {
                zs.avail_out = outlen * 2;
                inflated = static_cast<Bytef *>(realloc(inflated, outlen * 3));
                zs.next_out = inflated + outlen;
                outlen *= 3;
                zlib_return = inflate(&zs, Z_SYNC_FLUSH);
            }
        }

        if (zlib_return != Z_STREAM_END) {
            LOG_ERROR << "Zlib uncompress error, zlib-errno: " << zlib_return;
            delete[] inflated;
            return 0;
        }
        ulong infl_size = outlen - zs.avail_out;
        delete[] inflated;
        return infl_size;
    }
    return filesizeRaw;
}


int pcapfs::HttpFile::readChunked(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData;
    rawData.resize(filesizeRaw);
    readRaw(0, filesizeRaw, idx, (char *) rawData.data());

    Bytes out_buf;
    out_buf.resize(filesizeRaw);

    size_t raw_pos = 0;
    size_t out_pos = 0;

    bool incomplete_chunked = false;
    char *hex_end;
    while (true) {
        if (raw_pos >= rawData.size()) {
            break;
        }

        unsigned long chunk_size = strtoul((char *) rawData.data() + raw_pos, &hex_end, 16);
        //pass whitespaces \x20
        while (hex_end[0] == ' ') {
            ++hex_end;
        }
        if (!(hex_end[0] == '\r' && hex_end[1] == '\n') || raw_pos + chunk_size > filesizeRaw) {
            LOG_TRACE << "Error reading chunked encoding";
            incomplete_chunked = true;
            break;
        }
        raw_pos = hex_end - (char *) rawData.data() + 2;
        if (chunk_size == 0 || (buf != nullptr && out_pos >= startOffset + length)) {
            break;
        }
        memcpy((char *) out_buf.data() + out_pos, (char *) rawData.data() + raw_pos, chunk_size);
        raw_pos += chunk_size;
        out_pos += chunk_size;
        if (raw_pos >= filesizeRaw || !(rawData[raw_pos] == '\r' && rawData[raw_pos + 1] == '\n')) {
            LOG_TRACE << "Unexpected chunked encoding";
            incomplete_chunked = true;
            break;
        }
        raw_pos += 2;
    }

    if (incomplete_chunked) {
        //TODO: maybe set flags?
    }

    if (buf == nullptr) {
        LOG_ERROR << "no buffer specified in readChunked!";
    }
    if (out_pos == 0) {
        return 0;
    }

    size_t read_count = std::min((size_t) out_pos - startOffset, length);
    if (read_count == 0) {
        return 0;
    }
    memcpy(buf, (char *) out_buf.data() + startOffset, read_count);
    return (int) read_count;
}


int pcapfs::HttpFile::readDeflate(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData;
    rawData.resize(filesizeRaw + 1);
    uint64_t size;

    if (flags.test(pcapfs::flags::CHUNKED)) {
        size = readChunked(0, filesizeRaw, idx, (char *) rawData.data());
        rawData.resize(size);
    } else {
        readRaw(0, filesizeRaw, idx, (char *) rawData.data());
        size = filesizeRaw;
    }


    uInt inlen = static_cast<uInt>(size);
    uInt outlen = inlen * 5;
    Bytef *inflated = new Bytef[outlen];
    z_stream zs{};
    if (inflateInit2(&zs, MAX_WBITS) != Z_OK) {
        LOG_ERROR << "ZLIB init error";
        delete[] inflated;
        return 0;
    }

    zs.next_in = reinterpret_cast<Bytef *>((char *) rawData.data());
    zs.avail_in = inlen;
    zs.next_out = inflated;
    zs.avail_out = outlen;

    int zlib_return = inflate(&zs, Z_SYNC_FLUSH);
    while (zlib_return == Z_OK && zs.avail_out == 0) {
        zs.avail_out = outlen * 2;
        inflated = static_cast<Bytef *>(realloc(inflated, outlen * 3));
        zs.next_out = inflated + outlen;
        outlen *= 3;
        zlib_return = inflate(&zs, Z_SYNC_FLUSH);
    }
    if (zlib_return == Z_DATA_ERROR) {
        if (inflateReset2(&zs, -MAX_WBITS) != Z_OK) {
            LOG_ERROR << "ZLIB reset error";
            delete[] inflated;
            return 0;
        }

        zs.next_in = reinterpret_cast<Bytef *>((char *) rawData.data());
        zs.avail_in = inlen;
        zs.next_out = inflated;
        zs.avail_out = outlen;

        zlib_return = inflate(&zs, Z_SYNC_FLUSH);
        while (zlib_return == Z_OK && zs.avail_out == 0) {
            zs.avail_out = outlen * 2;
            inflated = static_cast<Bytef *>(realloc(inflated, outlen * 3));
            zs.next_out = inflated + outlen;
            outlen *= 3;
            zlib_return = inflate(&zs, Z_SYNC_FLUSH);
        }
    }

    if (zlib_return != Z_STREAM_END) {
        LOG_ERROR << "Zlib uncompress error, zlib-errno: " << zlib_return;
        delete[] inflated;
        return 0;
    }

    ulong infl_size = outlen - zs.avail_out;
    if (buf == nullptr) {
        LOG_ERROR << "no buffer specified in readDeflate!";
        delete[] inflated;
        return 0;
    }

    //size_t read_count = std::min((size_t) infl_size - startOffset, length);
    int read_count = std::min(infl_size - startOffset, length);
    if (read_count <= 0) {
        delete[] inflated;
        return 0;
    }

    memcpy(buf, inflated + startOffset, read_count);
    delete[] inflated;
    return (int) read_count;
}


bool pcapfs::HttpFile::isHttpTraffic(const Bytes &data) {
    if (data.size() >= 7) {
        std::string str(data.begin(), data.begin()+7);
        for (auto &s : httpStrings) {
            if (str.compare(0, s.length(), s) == 0)
                return true;
        }
    }
    return false;
}


//functions for HTTP parsing
bool pcapfs::HttpFile::isHTTPRequest(const Bytes &data, uint64_t startOffset, uint64_t length) {
    if (length == 0) {
        length = data.size();
    }
    LOG_INFO << "isHTTPRequest, early bird call: " << (char *) data.data() + startOffset;
    pcpp::HttpRequestLayer::HttpMethod method = pcpp::HttpRequestFirstLine::parseMethod(
            (char *) data.data() + startOffset, length);
    if (method == pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown) {
        return false;
    }
    if (!usesValidHTTPVersion(data, startOffset, length)) {
        return false;
    }
    return true;
}


pcpp::HttpRequestLayer::HttpMethod
pcapfs::HttpFile::getRequestMethod(const Bytes &data, uint64_t startOffset, size_t length) {
    if (length == 0) {
        length = data.size();
    }
    return pcpp::HttpRequestFirstLine::parseMethod((char *) data.data() + startOffset, length);
}


std::string pcapfs::HttpFile::requestMethodToString(pcpp::HttpRequestLayer::HttpMethod method) {
    const std::string methodEnumToString[9] = {
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "TRACE",
            "OPTIONS",
            "CONNECT",
            "PATCH"
    };

    if (method == pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown) {
        LOG_ERROR << "not a valid http method!";
    }
    return methodEnumToString[method];
}


bool pcapfs::HttpFile::usesValidHTTPVersion(const pcapfs::Bytes &data, uint64_t startOffset, size_t) {
    char *dataPtr = (char *) (data.data() + startOffset);
    char *verPos = strstr(dataPtr, "HTTP/");
    bool ret_val;
    if (verPos == nullptr) {
    	return false;
    }

    verPos += 5;
    switch (verPos[0]) {
        case '0':
            if (verPos[1] == '.' && verPos[2] == '9') {
            	ret_val = true;
            	break;
    		} else {
            	ret_val = false;
            	break;
            }
        case '1':
            if (verPos[1] == '.' && verPos[2] == '0') {
            	ret_val = true;
            	break;
            } else if (verPos[1] == '.' && verPos[2] == '1') {
            	ret_val = true;
            	break;
            } else {
            	ret_val = false;
            	break;
            }
        default:
            LOG_DEBUG << "Unsupported HTTP version " << (verPos - 5);
            ret_val = false;
            break;
    }
    return ret_val;
}


off_t pcapfs::HttpFile::getRequestUriOffset(const Bytes &data, uint64_t startOffset, size_t length) {
    if (length == 0) {
        length = data.size();
    }
    return pcapfs::HttpFile::requestMethodToString(
            pcapfs::HttpFile::getRequestMethod(data, startOffset, length)).length() + 1;
}


off_t pcapfs::HttpFile::getRequestVersionOffset(const Bytes &data, uint64_t startOffset, size_t length) {
    off_t uriOffset = getRequestUriOffset(data, startOffset, length);
    char *dataPtr = (char *) (data.data() + startOffset + uriOffset);
    char *verPos = strstr(dataPtr, " HTTP/");
    if (verPos == nullptr) {
        return 0;
    }
    return (verPos - dataPtr + uriOffset);
}


std::string pcapfs::HttpFile::getRequestUri(const Bytes &data, uint64_t startOffset, size_t length) {
    off_t uriOffset = getRequestUriOffset(data, startOffset, length);
    off_t versionOffset = getRequestVersionOffset(data, startOffset, length);
    if (uriOffset >= versionOffset) {
        return "";
    }
    std::string result(data.data() + startOffset + uriOffset, data.data() + startOffset + versionOffset);
    return result;
}


std::string pcapfs::HttpFile::uriToFilename(const std::string &uri) {
    std::vector<std::string> split_questionmark;
    std::vector<std::string> split_slash;
    boost::split(split_questionmark, uri, [](char c) { return c == '?' || c == ' ' || c == ';'; });
    boost::split(split_slash, split_questionmark[0], [](char c) { return c == '/'; });
    return split_slash.back();
}


size_t pcapfs::HttpFile::parseHeaderFields(const Bytes &data, pcapfs::headerMap &map, uint64_t startOffset,
                                                  size_t length) {
    char nameValueSeperator = ':';
    map.clear();
    size_t fieldSize = 0;
    size_t fieldNameSize = 0;
    size_t fieldValueSize = 0;
    size_t offsetInHeader = 0;
    bool isEndOfHeader = false;
    char *fieldData = (char *) (data.data() + startOffset);

    while (!isEndOfHeader and offsetInHeader < length) {
        char *fieldEndPtr = (char *) memchr(fieldData, '\n', length - offsetInHeader);

        if (fieldEndPtr == nullptr) {
            LOG_ERROR << "could not find end of http header field!";
            return 0;
        } else
            fieldSize = fieldEndPtr - fieldData + 1;

        if ((*fieldData) == '\r' or *(fieldData) == '\n') {
            offsetInHeader += 1;
            isEndOfHeader = true;
            if (*(fieldData + 1) == '\r' or *(fieldData + 1) == '\n') {
                offsetInHeader += 1;
            }
            break;
        } else {
            isEndOfHeader = false;
        }

        char *fieldValuePtr = (char *) memchr(fieldData, nameValueSeperator, length - offsetInHeader);
        // could not find the position of the separator, meaning field value position is unknown
        if (fieldValuePtr == nullptr) {
            LOG_ERROR << "could not find separator in HTTP header field!";
            break;
        } else {
            fieldNameSize = fieldValuePtr - fieldData;
            fieldValuePtr++;
            while ((static_cast<size_t>(fieldValuePtr - fieldData) <= length - offsetInHeader)
                   && *fieldValuePtr == ' ') {
                fieldValuePtr++;
            }
        }

        // reached the end of the packet and value start offset wasn't found
        if ((size_t) (fieldValuePtr - fieldData) > (length - offsetInHeader)) {
            LOG_ERROR << "could not find value in HTTP header field!";
        } else {
            //m_ValueOffsetInMessage = fieldValuePtr - (char*)m_TextBasedProtocolMessage->m_Data;
            // couldn't find the end of the field, so assuming the field value length is from m_ValueOffsetInMessage until the end of the packet
            fieldValueSize = fieldEndPtr - fieldValuePtr;
            // if field ends with \r\n, decrease the value length by 1
            if ((*(--fieldEndPtr)) == '\r') {
                fieldValueSize--;
            }
        }

        /*LOG_ERROR << "offsetin header is " << offsetInHeader << " field size was " << fieldSize << " fieldname length was "
                                                                                                << fieldNameSize <<
                  " field value size was " << fieldValueSize << " and still to read is " << (length - offsetInHeader);*/
        std::string fieldName(fieldData, fieldData + fieldNameSize);
        std::string fieldValue(fieldValuePtr, fieldValuePtr + fieldValueSize);

        boost::algorithm::to_lower(fieldName);
        map.insert({fieldName, fieldValue});
        //LOG_ERROR << "found field " << fieldName << " with value " << fieldValue << " and length " << std::to_string(fieldValueSize);
        offsetInHeader += fieldSize;
        fieldData += fieldSize;
    }

    //add to for last CRLF
    return offsetInHeader;
}


size_t pcapfs::HttpFile::getRequestLineLength(const Bytes &data, uint64_t startOffset, size_t length) {
    if (length == 0) {
        length = data.size();
    }

    //+9 for version number and +2 for CRNL
    return pcapfs::HttpFile::getRequestVersionOffset(data, startOffset, length) + 11;
}


bool pcapfs::HttpFile::isHTTPResponse(const Bytes &data, uint64_t startOffset, size_t length) {
    if (length == 0) {
        length = data.size();
    }
    if (getResponseStatusCode(data, startOffset, length) ==
        pcpp::HttpResponseLayer::HttpResponseStatusCode::HttpStatusCodeUnknown) {
    	LOG_INFO << "This is the content of isHTTPResponse: " << (char *) data.data() + startOffset;
        return false;
    }
    if (!usesValidHTTPVersion(data, startOffset, length)) {
        LOG_ERROR << "does not use valid HTTP in response check!";
        return false;
    }
    return true;
}


pcpp::HttpResponseLayer::HttpResponseStatusCode pcapfs::HttpFile::getResponseStatusCode(const Bytes &data,
                                                                                               uint64_t startOffset,
                                                                                               size_t length) {
    return pcpp::HttpResponseFirstLine::parseStatusCode((char *) data.data() + startOffset, length);
}


size_t pcapfs::HttpFile::getResponseLineLength(const Bytes &data, uint64_t startOffset, size_t length) {
    char *endOfFirstLine;

    if ((endOfFirstLine = (char *) memchr((char *) data.data() + startOffset, '\n', length)) != nullptr) {
        return (endOfFirstLine - (char *) (data.data() + startOffset) + 1);
    } else {
        return 0;
    }
}

void pcapfs::HttpFile::serialize(boost::archive::text_oarchive &archive) {
    VirtualFile::serialize(archive);
    if (flags.test(pcapfs::flags::COBALT_STRIKE)) {
        archive << cobaltStrikeKey;
        archive << (fromClient ? 1 : 0);
        archive << csEmbeddedFileIndex;
    }

}

void pcapfs::HttpFile::deserialize(boost::archive::text_iarchive &archive) {
    VirtualFile::deserialize(archive);
    if (flags.test(pcapfs::flags::COBALT_STRIKE)) {
        int i;
        archive >> cobaltStrikeKey;
        archive >> i;
        fromClient = i ? true : false;
        archive >> csEmbeddedFileIndex;
    }
}


bool pcapfs::HttpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("http", pcapfs::HttpFile::create, pcapfs::HttpFile::parse);
