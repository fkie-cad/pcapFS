#include "dns.h"

#include <string>

#include <nlohmann/json.hpp>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsResourceData.h>

#include "../filefactory.h"
#include "../logging.h"
#include "../properties.h"


namespace prop = pcapfs::prop;


namespace {

    const char *FILE_TYPE_NAME = "dns";


    std::string dnsClassToString(const pcpp::DnsClass dnsClass) {
        static const std::string dnsClasses[]{"Unknown (0)", "IN", "IN_QU", "CH", "HS"};
        static const size_t dnsClassesAvailable = 5;

        if (dnsClass == pcpp::DnsClass::DNS_CLASS_ANY) {
            return "ALL";
        } else if (dnsClass >= dnsClassesAvailable) {
            return ("Unknown (" + std::to_string(dnsClass) + ")");
        } else {
            return dnsClasses[dnsClass];
        }
    }


    std::string dnsTypeToString(pcpp::DnsType type) {
        static const std::string dnsType[]
                {"Unknown (0)", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL_R", "WKS", "PTR",
                 "HINFO", "MINFO",
                 "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP_PTR", "SIG", "KEY", "PX", "GPOS",
                 "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAM", "SINK",
                 "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM"};
        static const size_t dnsTypesAvailable = 52;

        if (type == pcpp::DnsType::DNS_TYPE_ALL) {
            return "ALL";
        } else if (type >= dnsTypesAvailable) {
            return ("Unknown (" + std::to_string(type) + ")");
        } else {
            return dnsType[type];
        }
    }

    std::vector<nlohmann::json> parseDnsAnswersToJson(pcpp::DnsLayer &dnsLayer) {
        //process answers in dns packet (for responses)
        std::vector<nlohmann::json> answers = std::vector<nlohmann::json>();
        pcpp::DnsResource *ans = dnsLayer.getFirstAnswer();

        if (ans != nullptr) {
            while (ans != nullptr) {
                std::unordered_map<std::string, std::string> answerValues = {{"name",  ans->getName().c_str()},
                                     {"data",  pcapfs::DnsFile::getDataAsString(ans)},
                                     {"ttl",   std::to_string(ans->getTTL())},
                                     {"type",  dnsTypeToString(ans->getDnsType())},
                                     {"class", dnsClassToString(ans->getDnsClass())}};


                if(ans->getDnsType() == pcpp::DNS_TYPE_MX){
                    answerValues.insert({"preference", std::to_string(
                            ans->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().preference)});
                }
                answers.emplace_back(answerValues);
                ans = dnsLayer.getNextAnswer(ans);
            }
        }
        return answers;
    }


    std::string parseDnsToJson(pcapfs::Bytes data) {
        pcpp::Packet packet;
        pcpp::DnsLayer newDnsLayer;
        newDnsLayer = pcpp::DnsLayer(data.data(), data.size(), nullptr, &packet);
        nlohmann::json output_json;
        output_json["ID"] = std::to_string(newDnsLayer.getDnsHeader()->transactionID);
        //process queries in dns packet (for requests and responses)
        std::vector<nlohmann::json> queries;

        pcpp::DnsQuery *qry = newDnsLayer.getFirstQuery();

        if (qry != nullptr) {
            while (qry != nullptr) {
                queries.push_back({{"type",  dnsTypeToString(qry->getDnsType())},
                                   {"name",  qry->getName()},
                                   {"class", dnsClassToString(qry->getDnsClass())}});

                qry = newDnsLayer.getNextQuery(qry);
            }
            output_json["Queries"] = queries;
        }
        //check if response
        if (newDnsLayer.getDnsHeader()->queryOrResponse) {

            output_json["Answers"] = parseDnsAnswersToJson(newDnsLayer);

            //process authorities in dns packet (for responses)
            pcpp::DnsResource *auth = newDnsLayer.getFirstAuthority();
            if (auth == nullptr) {
                output_json["Authorities"] = std::vector<nlohmann::json>();
            } else {
                std::vector<nlohmann::json> auths;
                while (auth != nullptr) {
                    auths.push_back({{"auth", auth->getName()},
                                     {"ttl",  std::to_string(auth->getTTL())}});
                    auth = newDnsLayer.getNextAuthority(auth);
                }
                output_json["Authorities"] = auths;
            }
        }

        std::string output_string = output_json.dump(1, '\t');
        return output_string;
    }


}


std::vector<pcapfs::FilePtr> pcapfs::DnsFile::parse(FilePtr filePtr, Index &idx) {
    Bytes data = filePtr->getBuffer();
    std::vector<pcapfs::FilePtr> resultVector;
    //right now, assume one udp virtual file contains one dns request/response
    pcpp::Packet packet;
    pcpp::DnsLayer dns;
    Fragment fragment{};
    std::shared_ptr<pcapfs::DnsFile> resultPtr = std::make_shared<pcapfs::DnsFile>();

    if ((filePtr->getProperty(prop::dstPort) == "53" || filePtr->getProperty(prop::srcPort) == "53") &&
        filePtr->getProperty(prop::proto) == "udp") {
        dns = pcpp::DnsLayer(data.data(), data.size(), nullptr, &packet);
        fragment.id = filePtr->getIdInIndex();
        fragment.start = 0;
        fragment.length = filePtr->getFilesizeRaw();
        resultPtr->fragments.push_back(fragment);
        resultPtr->setFilesizeRaw(fragment.length);

        //We assume the processed file size does not change in this protocol in cmp to the raw file size
        resultPtr->setFilesizeProcessed(fragment.length);

        resultPtr->setOffsetType(filePtr->getFiletype());
        resultPtr->setFiletype(FILE_TYPE_NAME);
        resultPtr->setTimestamp(filePtr->getTimestamp());
        resultPtr->setProperty(prop::srcIp, filePtr->getProperty(prop::srcIp));
        resultPtr->setProperty(prop::dstIp, filePtr->getProperty(prop::dstIp));
        resultPtr->setProperty(prop::srcPort, filePtr->getProperty(prop::srcPort));
        resultPtr->setProperty(prop::dstPort, filePtr->getProperty(prop::dstPort));
        resultPtr->setProperty(prop::proto, FILE_TYPE_NAME);
        resultPtr->flags.set(pcapfs::flags::PROCESSED);

        resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));


        if (filePtr->getProperty(prop::dstPort) == "53") {
            //TODO: add type of query to file name ?
            resultPtr->setFilename("REQ-" + std::to_string(dns.getDnsHeader()->transactionID));
        } else if (filePtr->getProperty(prop::srcPort) == "53") {
            resultPtr->setFilename("RES-" + std::to_string(dns.getDnsHeader()->transactionID));
        }
        resultVector.push_back(resultPtr);
    }
    return resultVector;
}


size_t pcapfs::DnsFile::calculateProcessedSize(const Index &idx) {
    Bytes rawData;
    rawData.resize(filesizeRaw);
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(0 + fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    std::string output_string = parseDnsToJson(rawData);
    return output_string.size();
}


size_t pcapfs::DnsFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    Bytes rawData;
    Fragment fragment = fragments.at(0);
    rawData.resize(fragment.length);
    FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(0 + fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    const auto output_string = parseDnsToJson(rawData);
    size_t read_count = std::min((size_t) output_string.length() - startOffset, length);
    memcpy(buf, output_string.c_str() + startOffset, length);
    return read_count;
}

std::string pcapfs::DnsFile::getDataAsString(pcpp::DnsResource *resource) {
    if (resource->getDnsType() == pcpp::DNS_TYPE_A or resource->getDnsType() == pcpp::DNS_TYPE_AAAA) {
        return resource->getData()->toString();
    } else if (resource->getDnsType() == pcpp::DNS_TYPE_MX) {
        return resource->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().mailExchange.c_str();
    } else {
        return "";
    }
}

bool pcapfs::DnsFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory(FILE_TYPE_NAME, pcapfs::DnsFile::create, pcapfs::DnsFile::parse);
