#ifndef PCAPFS_VIRTUAL_FILES_HTTP_H
#define PCAPFS_VIRTUAL_FILES_HTTP_H

#include <pcapplusplus/HttpLayer.h>

#include "virtualfile.h"


namespace pcapfs {
    typedef std::map<std::string, std::string> headerMap;

    class HttpFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<HttpFile>(); };

        //TODO: make this virtual in superclass?
        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);

        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

        int readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        int readGzip(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        int readDeflate(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        int readChunked(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        int calculateProcessedSize(const Index &idx);


        //functions used for http parsing
        static bool isHttpTraffic(const FilePtr& filePtr);

        static bool isHTTPRequest(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static size_t getRequestLineLength(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static pcpp::HttpRequestLayer::HttpMethod
        getRequestMethod(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static std::string requestMethodToString(pcpp::HttpRequestLayer::HttpMethod method);

        static off_t getRequestVersionOffset(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static std::string getRequestUri(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static off_t getRequestUriOffset(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static bool isHTTPResponse(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static pcpp::HttpResponseLayer::HttpResponseStatusCode
        getResponseStatusCode(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static size_t getResponseLineLength(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static std::string uriToFilename(const std::string &uri);

        static size_t parseHeaderFields(const Bytes &data, headerMap &map, uint64_t startOffset = 0, size_t length = 0);

        static bool usesValidHTTPVersion(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

    protected:
        static bool registeredAtFactory;

    };

}

#endif //PCAPFS_VIRTUAL_FILES_HTTP_H
