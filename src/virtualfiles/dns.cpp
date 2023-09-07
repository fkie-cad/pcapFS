#include "dns.h"

#include <string>
#include <nlohmann/json.hpp>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DnsResourceData.h>

#include "../filefactory.h"
#include "../logging.h"
#include "udp.h"


std::string const pcapfs::DnsFile::dnsClassToString(const pcpp::DnsClass dnsClass) {
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


std::string const pcapfs::DnsFile::dnsTypeToString(pcpp::DnsType type) {
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


std::vector<nlohmann::json> const pcapfs::DnsFile::parseDnsAnswersToJson(const pcpp::DnsLayer &dnsLayer) {
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


std::string const pcapfs::DnsFile::parseDnsToJson(pcapfs::Bytes data) {
    pcpp::Packet packet;
    const pcpp::DnsLayer newDnsLayer(data.data(), data.size(), nullptr, &packet);
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

    return output_json.dump(1, '\t');
}


std::vector<pcapfs::FilePtr> pcapfs::DnsFile::parse(FilePtr filePtr, Index &idx) {
    std::vector<pcapfs::FilePtr> resultVector;

    if (!((filePtr->getProperty("dstPort") == "53" || filePtr->getProperty("srcPort") == "53") &&
        filePtr->getProperty("protocol") == "udp"))
        return resultVector;

    Bytes data = filePtr->getBuffer();
    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();
    LOG_TRACE << "number of connection breaks aka future DNS files: " << numElements;

    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = filePtr->connectionBreaks.at(i).first;
        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        const std::shared_ptr<UdpFile> udpFile = std::dynamic_pointer_cast<UdpFile>(filePtr);

        for (const Fragment &udpFrag : udpFile->fragments) {
            std::shared_ptr<pcapfs::DnsFile> resultPtr = std::make_shared<pcapfs::DnsFile>();
            pcpp::Packet packet;
            const pcpp::DnsLayer dnsLayer = pcpp::DnsLayer(data.data() + offset, udpFrag.length, nullptr, &packet);

            Fragment fragment;
            fragment.id = filePtr->getIdInIndex();
            fragment.start = offset;
            fragment.length = dnsLayer.getHeaderLen();
            resultPtr->fragments.push_back(fragment);

            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilesizeProcessed(fragment.length);
            resultPtr->setOffsetType("udp");
            resultPtr->setFiletype("dns");
            resultPtr->setTimestamp(filePtr->connectionBreaks.at(i).second);
            if (i % 2 == 0) {
                resultPtr->setProperty("srcIP", filePtr->getProperty("srcIP"));
                resultPtr->setProperty("dstIP", filePtr->getProperty("dstIP"));
                resultPtr->setProperty("srcPort", filePtr->getProperty("srcPort"));
                resultPtr->setProperty("dstPort", filePtr->getProperty("dstPort"));
            } else {
                resultPtr->setProperty("srcIP", filePtr->getProperty("dstIP"));
                resultPtr->setProperty("dstIP", filePtr->getProperty("srcIP"));
                resultPtr->setProperty("srcPort", filePtr->getProperty("dstPort"));
                resultPtr->setProperty("dstPort", filePtr->getProperty("srcPort"));
            }
            resultPtr->setProperty("protocol", "dns");
            resultPtr->flags.set(pcapfs::flags::PROCESSED);

            resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));

            if (filePtr->getProperty("dstPort") == "53") {
                resultPtr->setFilename("REQ-" + std::to_string(dnsLayer.getDnsHeader()->transactionID));
            } else if (filePtr->getProperty("srcPort") == "53") {
                resultPtr->setFilename("RES-" + std::to_string(dnsLayer.getDnsHeader()->transactionID));
            }
            resultVector.push_back(resultPtr);

            offset += dnsLayer.getHeaderLen();
            if (offset >= size)
                break;
        }
    }
    return resultVector;
}


size_t pcapfs::DnsFile::calculateProcessedSize(const Index &idx) {
    const Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    const FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(0 + fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    return parseDnsToJson(rawData).size();
}


size_t pcapfs::DnsFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    const Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    const FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    const std::string output_string = parseDnsToJson(rawData);
    memcpy(buf, output_string.c_str() + startOffset, length);
    return std::min((size_t) output_string.length() - startOffset, length);
}


std::string const pcapfs::DnsFile::getDataAsString(pcpp::DnsResource *resource) {
    if (resource->getDnsType() == pcpp::DNS_TYPE_A or resource->getDnsType() == pcpp::DNS_TYPE_AAAA) {
        return resource->getData()->toString();
    } else if (resource->getDnsType() == pcpp::DNS_TYPE_MX) {
        return resource->getData()->castAs<pcpp::MxDnsResourceData>()->getMxData().mailExchange.c_str();
    } else {
        return "";
    }
}


bool pcapfs::DnsFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("dns", pcapfs::DnsFile::create, pcapfs::DnsFile::parse);
