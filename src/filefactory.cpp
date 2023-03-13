#include "filefactory.h"

#include "logging.h"
#include "capturefiles/pcap.h"


std::map<std::string, pcapfs::FileFactory::CreateMethod> &pcapfs::FileFactory::getFactoryFileTypes() {
    static std::map<std::string, CreateMethod> g_;
    return g_;
};


std::map<std::string, pcapfs::FileFactory::ParseMethod> &pcapfs::FileFactory::getFactoryParseMethods() {
    static std::map<std::string, ParseMethod> g_;
    return g_;
};


bool pcapfs::FileFactory::registerAtFactory(const std::string &type, pcapfs::FileFactory::CreateMethod createMethod) {
    auto it = getFactoryFileTypes().find(type);
    if (it == getFactoryFileTypes().end()) {
        getFactoryFileTypes().insert({type, createMethod});
        #if(DEBUG)
            LOG_DEBUG << "registered file type: " << type;
        #endif
        return true;
    } else {
        return false;
    }
}


bool
pcapfs::FileFactory::registerAtFactory(const std::string &type, CreateMethod createMethod, ParseMethod parseMethod) {
    auto it = getFactoryFileTypes().find(type);
    if (it == getFactoryFileTypes().end()) {
        getFactoryFileTypes().insert({type, createMethod});
        getFactoryParseMethods().insert({type, parseMethod});
        #if(DEBUG)
            LOG_DEBUG << "registered file type: " << type;
        #endif
        return true;
    } else {
        return false;
    }
}


pcapfs::FilePtr pcapfs::FileFactory::createFilePtr(const std::string &type) {
    auto it = getFactoryFileTypes().find(type);
    if (it != getFactoryFileTypes().end()) {
        return it->second();
    }
    return nullptr;
}
