#include "http.h"
#include "../filefactory.h"
#include "../logging.h"
#include "cobaltstrike/cs_manager.h"
#include "../crypto/ja4.h"

#include <boost/algorithm/string.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/RawPacket.h>
#include <zlib.h>


/*
 * HTTP Parsing function.
 * Is always called for a file that is classified as HTTP.
 */
std::vector<pcapfs::FilePtr> pcapfs::HttpFile::parse(pcapfs::FilePtr filePtr, pcapfs::Index &idx) {
    const Bytes data = filePtr->getBuffer();
    std::vector<FilePtr> resultVector(0);

    if(!isHttpTraffic(data)){
        return resultVector;
    }

    size_t size = 0;
    std::string requestedFilename;
    std::string requestedHost;
    std::string requestedUri;
    std::string ja4h;
    bool prevWasRequest = false;
    const size_t numElements = filePtr->connectionBreaks.size();
    pcpp::Packet tmpPacket;

    LOG_TRACE << "HTTP parser, number of elements (connection breaks): " << numElements;

    for (unsigned int i = 0; i < numElements; ++i) {
        const uint64_t &offset = filePtr->connectionBreaks.at(i).first;
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
            ja4h = "";
        }

        if (isHTTPRequest(data, offset, size)) {
            LOG_TRACE << "parsing http request";
            const pcpp::HttpRequestLayer requestLayer((uint8_t *) (data.data() + offset), size, nullptr, &tmpPacket);
            const size_t headerLength = requestLayer.getHeaderLen();
            if (headerLength == 0 || headerLength > size) {
                LOG_WARNING << "encountered invalid http header length, we skip that.";
                continue;
            }
            prevWasRequest = true;

            //create header of http request
            fragmentHeader.start = offset;
            fragmentHeader.length = headerLength;
            resultHeaderPtr->fragments.push_back(fragmentHeader);
            resultHeaderPtr->setFilesizeRaw(fragmentHeader.length);

            const pcpp::HeaderField* hostField = requestLayer.getFieldByName("Host");
            if (hostField)
                requestedHost = hostField->getFieldValue();

            const pcpp::HttpRequestFirstLine* firstLine = requestLayer.getFirstLine();
            if (!firstLine)
                continue;
            requestedUri = firstLine->getUri();
            requestedFilename = uriToFilename(requestedUri);

            LOG_TRACE << "requestedFilename: " << requestedFilename
            		<< " - requestedHost: " << requestedHost
        			<< " - requestedUri: " << requestedUri;
            LOG_TRACE << "fileSizeRaw: " << fragmentHeader.length;

            const std::string requestMethod = requestMethodToString(firstLine->getMethod());

            ja4h = ja4::calculateJa4H(requestLayer, requestMethod);

            if (requestedFilename != "") {
                resultHeaderPtr->setFilename(requestMethod + "-" + requestedFilename);
            } else {
                resultHeaderPtr->setFilename(requestMethod);
            }

            resultHeaderPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultHeaderPtr->fillFileProperties(filePtr, true);
            resultHeaderPtr->setProperty("domain", requestedHost);
            resultHeaderPtr->setProperty("uri", requestedUri);
            resultHeaderPtr->setProperty("ja4h", ja4h);
            resultHeaderPtr->flags.set(pcapfs::flags::IS_METADATA);

            resultVector.push_back(resultHeaderPtr);

            if ((!config.noCS && requestMethod == "GET" && requestLayer.getFieldByName("Cookie") && !idx.getCandidatesOfType("cskey").empty() &&
                (config.getDecodeMapFor("cobaltstrike").empty() || filePtr->meetsDecodeMapCriteria("cobaltstrike"))) ||
                (config.noCS && filePtr->meetsDecodeMapCriteria("cobaltstrike"))) {
                // when no decode config for cobaltstrike is supplied but a cobaltstrike key, we check all HTTP GET cookies;
                // when a cs decode config is supplied we only handle cookies belonging to a tcp file which meets the given config;
                // if the flag --no-cs is set we handle the cookie nevertheless if the tcp file meets a given config
                CobaltStrikeManager::getInstance().handleHttpGet(requestLayer.getFieldByName("Cookie")->getFieldValue(), filePtr->getProperty("dstIP"),
                                                                    filePtr->getProperty("dstPort"), filePtr->getProperty("srcIP"), idx);
            }

            LOG_TRACE << "size: " << size << " - headerLength: " << headerLength;
            // when there is no http request body, we continue
            if (size - headerLength == 0) {
                continue;
            }

            //create http request body
            LOG_TRACE << "parsing http request body";
            fragment.start = offset + headerLength;
            fragment.length = size - headerLength;
            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);

            if (requestedFilename != "") {
                resultPtr->setFilename(requestMethod + "-" + requestedFilename);
            } else {
                resultPtr->setFilename(requestMethod);
            }

            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->fillFileProperties(filePtr, true);
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);
            resultPtr->setProperty("ja4h", ja4h);

            resultVector.push_back(resultPtr);

        } else if (isHTTPResponse(data, offset, size)) {
            LOG_TRACE << "parsing http response";

            const pcpp::HttpResponseLayer responseLayer((uint8_t *) (data.data() + offset), size, nullptr, &tmpPacket);
            const size_t headerLength = responseLayer.getHeaderLen();
            if (headerLength == 0 || headerLength > size) {
                LOG_WARNING << "encountered invalid http header length, we skip that.";
                continue;
            }

            //create header of http response
            fragmentHeader.start = offset;
            fragmentHeader.length = headerLength;
            resultHeaderPtr->fragments.push_back(fragmentHeader);
            resultHeaderPtr->setFilesizeRaw(fragmentHeader.length);
            resultHeaderPtr->setFilename(requestedFilename);
            resultHeaderPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultHeaderPtr->fillFileProperties(filePtr, false);
            resultHeaderPtr->setProperty("domain", requestedHost);
            resultHeaderPtr->setProperty("uri", requestedUri);
            if (!ja4h.empty()) {
                resultHeaderPtr->setProperty("ja4h", ja4h);
                resultPtr->setProperty("ja4h", ja4h);
            }
            resultHeaderPtr->flags.set(pcapfs::flags::IS_METADATA);

            resultVector.push_back(resultHeaderPtr);

            // when there is no http response body, we continue
            if (size - headerLength == 0) {
                continue;
            }

            //create http response body
            LOG_TRACE << "parsing http response body";
            fragment.start = offset + headerLength;
            fragment.length = size - headerLength;
            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilename(requestedFilename);
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->fillFileProperties(filePtr, false);
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);

            if (responseLayer.getFieldByName("transfer-encoding") &&
                responseLayer.getFieldByName("transfer-encoding")->getFieldValue() == "chunked") {
                resultPtr->flags.set(pcapfs::flags::CHUNKED);
                resultPtr->flags.set(pcapfs::flags::PROCESSED);
                LOG_TRACE << "detected chunked content";
            }
            if (responseLayer.getFieldByName("content-encoding")) {
                const std::string contentEncoding = responseLayer.getFieldByName("content-encoding")->getFieldValue();
                if (contentEncoding == "gzip") {
                    resultPtr->flags.set(pcapfs::flags::COMPRESSED_GZIP);
                    resultPtr->flags.set(pcapfs::flags::PROCESSED);
                    LOG_TRACE << "detected gzip content";
                }
                else if (contentEncoding == "deflate") {
                    resultPtr->flags.set(pcapfs::flags::COMPRESSED_DEFLATE);
                    resultPtr->flags.set(pcapfs::flags::PROCESSED);
                    LOG_TRACE << "detected deflate content";
                }
            }

            resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));
            LOG_TRACE << "calculateProcessedSize got: " << resultPtr->getFilesizeProcessed();
            if (resultPtr->getFilesizeProcessed() == 0) {
                continue;
            }
            prevWasRequest = false;

            resultVector.push_back(resultPtr);

        } else if(prevWasRequest && config.allowHTTP09) {

            if (size == 0) {
                continue;
            }

            //create http response body
            fragment.start = offset;
            fragment.length = size;
            resultPtr->fragments.push_back(fragment);
            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilename(requestedFilename);
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            resultPtr->fillFileProperties(filePtr, false);
            resultPtr->setProperty("domain", requestedHost);
            resultPtr->setProperty("uri", requestedUri);

            // HTTP0.9 has no compression
            /**if (header["transfer-encoding"] == "chunked") {
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
            }**/

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


size_t pcapfs::HttpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    if (flags.test(pcapfs::flags::COMPRESSED_GZIP)) {
        return readGzip(startOffset, length, idx, buf);
    } else if (flags.test(pcapfs::flags::COMPRESSED_DEFLATE)) {
        return readDeflate(startOffset, length, idx, buf);
    } else if (flags.test(pcapfs::flags::CHUNKED)) {
        return readChunked(startOffset, length, idx, buf);
    } else {
        return readRaw(startOffset, length, idx, buf);
    }
}


int pcapfs::HttpFile::readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    //TODO: right now this assumes each http file only contains ONE offset into a tcp stream
    Fragment fragment = fragments.at(0);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    //TODO: sanitizing length is done in filePtr->read!
    return filePtr->read(startOffset + fragment.start, length, idx, buf);
}


int pcapfs::HttpFile::readGzip(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData(filesizeRaw + 1);
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
    }

    const int readCount = (int) std::min((size_t) decr_size - startOffset, length);
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
    Bytes data(filesizeRaw);

    if (flags.test(pcapfs::flags::CHUNKED)) {
        const int chunkedSize = readChunked(0, filesizeRaw, idx, (char *) data.data());
        if (chunkedSize == 0) {
            return 0;
        }
        data.resize(chunkedSize);
    } else {
        readRaw(0, filesizeRaw, idx, (char *) data.data());
    }

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
        const ulong infl_size = outlen - zs.avail_out;
        delete[] inflated;
        return infl_size;
    }
    return filesizeRaw;
}


int pcapfs::HttpFile::readChunked(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData(filesizeRaw);
    readRaw(0, filesizeRaw, idx, (char *) rawData.data());

    Bytes out_buf(filesizeRaw);
    size_t raw_pos = 0;
    size_t out_pos = 0;

    bool incomplete_chunked = false;
    char *hex_end;
    while (true) {
        if (raw_pos >= rawData.size()) {
            break;
        }

        const unsigned long chunk_size = strtoul((char *) rawData.data() + raw_pos, &hex_end, 16);
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
        if (raw_pos >= filesizeRaw || !(rawData.at(raw_pos) == '\r' && rawData.at(raw_pos + 1) == '\n')) {
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

    const size_t read_count = std::min((size_t) out_pos - startOffset, length);
    if (read_count == 0) {
        return 0;
    }
    memcpy(buf, (char *) out_buf.data() + startOffset, read_count);
    return (int) read_count;
}


int pcapfs::HttpFile::readDeflate(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData(filesizeRaw + 1);
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

    const ulong infl_size = outlen - zs.avail_out;
    if (buf == nullptr) {
        LOG_ERROR << "no buffer specified in readDeflate!";
        delete[] inflated;
        return 0;
    }

    //size_t read_count = std::min((size_t) infl_size - startOffset, length);
    const int read_count = std::min(infl_size - startOffset, length);
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
        const std::string str(data.begin(), data.begin()+7);
        for (auto &s : httpMethods) {
            if (str.compare(0, s.length(), s) == 0)
                return true;
        }
    }
    return false;
}


bool pcapfs::HttpFile::isHTTPRequest(const Bytes &data, uint64_t startOffset, uint64_t length) {
    if (length == 0) {
        length = data.size();
    }
    LOG_TRACE << "checking isHTTPRequest";

    pcpp::Packet tmpPacket;
    const pcpp::HttpRequestLayer requestLayer((uint8_t *) (data.data() + startOffset), length, nullptr, &tmpPacket);
    const pcpp::HttpRequestFirstLine* firstLine = requestLayer.getFirstLine();
    if(firstLine->getMethod() == pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown ||
        firstLine->getVersion() == pcpp::HttpVersion::HttpVersionUnknown || !requestLayer.isHeaderComplete())
        return false;
    return true;
}


std::string const pcapfs::HttpFile::requestMethodToString(const pcpp::HttpRequestLayer::HttpMethod &method) {
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
        LOG_ERROR << "caught an invalid http method";
        return "UNKNOWN";
    }
    return methodEnumToString[method];
}


std::string const pcapfs::HttpFile::uriToFilename(const std::string &uri) {
    std::vector<std::string> split_questionmark;
    std::vector<std::string> split_slash;
    boost::split(split_questionmark, uri, [](char c) { return c == '?' || c == ' ' || c == ';'; });
    boost::split(split_slash, split_questionmark.at(0), [](char c) { return c == '/'; });
    return split_slash.back();
}


bool pcapfs::HttpFile::isHTTPResponse(const Bytes &data, uint64_t startOffset, size_t length) {
    if (length == 0) {
        length = data.size();
    }
    LOG_TRACE << "checking isHTTPResponse";

    pcpp::Packet tmpPacket;
    const pcpp::HttpResponseLayer responseLayer((uint8_t *) (data.data() + startOffset), length, nullptr, &tmpPacket);
    const pcpp::HttpResponseFirstLine* firstLine = responseLayer.getFirstLine();
    if(firstLine->getStatusCode() == pcpp::HttpResponseLayer::HttpResponseStatusCode::HttpStatusCodeUnknown ||
        firstLine->getVersion() == pcpp::HttpVersionUnknown || !responseLayer.isHeaderComplete())
        return false;
    return true;
}


void pcapfs::HttpFile::fillFileProperties(const FilePtr &filePtr, bool isRequest) {
    setOffsetType(filePtr->getFiletype());
    setFilesizeProcessed(filesizeRaw);
    setFiletype("http");
    setProperty("protocol", "http");
    if (!filePtr->getProperty("ja3").empty())
        setProperty("ja3", filePtr->getProperty("ja3"));
    if (!filePtr->getProperty("ja3s").empty())
        setProperty("ja3s", filePtr->getProperty("ja3s"));
    if (!filePtr->getProperty("ja4").empty())
        setProperty("ja4", filePtr->getProperty("ja4"));
    if (!filePtr->getProperty("ja4s").empty())
        setProperty("ja4s", filePtr->getProperty("ja4s"));
    if (!filePtr->getProperty("ja4x").empty())
        setProperty("ja4x", filePtr->getProperty("ja4x"));
    if (filePtr->flags.test(pcapfs::flags::MISSING_DATA))
        flags.set(pcapfs::flags::MISSING_DATA);

    if (isRequest) {
        setProperty("srcIP", filePtr->getProperty("srcIP"));
        setProperty("dstIP", filePtr->getProperty("dstIP"));
        setProperty("srcPort", filePtr->getProperty("srcPort"));
        setProperty("dstPort", filePtr->getProperty("dstPort"));
    } else {
        setProperty("srcIP", filePtr->getProperty("dstIP"));
        setProperty("dstIP", filePtr->getProperty("srcIP"));
        setProperty("srcPort", filePtr->getProperty("dstPort"));
        setProperty("dstPort", filePtr->getProperty("srcPort"));
    }
}


bool pcapfs::HttpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("http", pcapfs::HttpFile::create, pcapfs::HttpFile::parse);
