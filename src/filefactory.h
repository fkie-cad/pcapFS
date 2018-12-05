#ifndef PCAPFS_FILE_FACTORY_H
#define PCAPFS_FILE_FACTORY_H

#include <map>
#include <string>
#include <vector>

#include "file.h"
#include "index.h"


namespace pcapfs {
    class FileFactory {

    public:
        FileFactory() = delete;

        using CreateMethod = FilePtr(*)();
        using ParseMethod = std::vector<FilePtr>(*)(FilePtr filePtr, Index &idx);

        static FilePtr createFilePtr(const std::string &type);

        static std::vector<FilePtr> parseFile(FilePtr filePtr, const Index &idx);

        static bool registerAtFactory(const std::string &type, CreateMethod createMethod);

        static bool registerAtFactory(const std::string &type, CreateMethod createMethod, ParseMethod parseMethod);

        static std::vector<std::string> getFiletypes();


        static std::map<std::string, ParseMethod> &getFactoryParseMethods();

    private:
        static std::map<std::string, CreateMethod> &getFactoryFileTypes();
    };

}

#endif //PCAPFS_FILE_FACTORY_H
