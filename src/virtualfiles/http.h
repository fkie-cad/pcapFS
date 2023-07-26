#ifndef PCAPFS_VIRTUAL_FILES_HTTP_H
#define PCAPFS_VIRTUAL_FILES_HTTP_H

#include <set>
#include <pcapplusplus/HttpLayer.h>

#include "virtualfile.h"


namespace pcapfs {

    const std::set<std::string> httpMethods = {"HTTP", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

    class HttpFile : public VirtualFile {
    public:
        static FilePtr create() { return std::make_shared<HttpFile>(); };

        static std::vector<FilePtr> parse(FilePtr filePtr, Index &idx);
        size_t read(uint64_t startOffset, size_t length, const Index &idx, char *buf) override;

    private:
        int readRaw(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        int readGzip(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        int readDeflate(uint64_t startOffset, size_t length, const Index &idx, char *buf);
        int readChunked(uint64_t startOffset, size_t length, const Index &idx, char *buf);

        static bool isHttpTraffic(const Bytes &data);
        static bool isHTTPRequest(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);
        static bool isHTTPResponse(const Bytes &data, uint64_t startOffset = 0, size_t length = 0);

        static std::string const requestMethodToString(const pcpp::HttpRequestLayer::HttpMethod &method);
        static std::string const uriToFilename(const std::string &uri);

        int calculateProcessedSize(const Index &idx);

        void fillFileProperties(const FilePtr &filePtr, bool isRequest);

    protected:
        static bool registeredAtFactory;
    };

}

#endif //PCAPFS_VIRTUAL_FILES_HTTP_H
