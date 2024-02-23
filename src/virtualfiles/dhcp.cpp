#include "dhcp.h"

#include <string>
#include <algorithm>
#include <set>
#include <nlohmann/json.hpp>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/DhcpLayer.h>

#include "../filefactory.h"
#include "../logging.h"
#include "dhcp_options.h"
#include "udp.h"


std::vector<pcapfs::FilePtr> pcapfs::DhcpFile::parse(FilePtr filePtr, Index &idx) {
    std::vector<pcapfs::FilePtr> resultVector(0);
    if (!isDhcpTraffic(filePtr))
        return resultVector;

    LOG_TRACE << "starting DHCP parser";
    Bytes data = filePtr->getBuffer();
    size_t size = 0;
    const size_t numElements = filePtr->connectionBreaks.size();
    LOG_TRACE << "number of connection breaks aka future DHCP files: " << numElements;
    const std::shared_ptr<UdpFile> udpFile = std::dynamic_pointer_cast<UdpFile>(filePtr);

    for (unsigned int i = 0; i < numElements; ++i) {
        uint64_t offset = filePtr->connectionBreaks.at(i).first;
        if (i == numElements - 1) {
        	size = filePtr->getFilesizeProcessed() - offset;
        } else {
            size = filePtr->connectionBreaks.at(i + 1).first - offset;
        }

        for (const Fragment &udpFrag : udpFile->fragments) {
            std::shared_ptr<pcapfs::DhcpFile> resultPtr = std::make_shared<pcapfs::DhcpFile>();
            pcpp::Packet packet;
            const pcpp::DhcpLayer dhcpLayer(data.data() + offset, udpFrag.length, nullptr, &packet);

            Fragment fragment;
            fragment.id = filePtr->getIdInIndex();
            fragment.start = offset;
            fragment.length = udpFrag.length;
            resultPtr->fragments.push_back(fragment);

            resultPtr->setFilesizeRaw(fragment.length);
            resultPtr->setFilesizeProcessed(fragment.length);
            resultPtr->setOffsetType("udp");
            resultPtr->setFiletype("dhcp");
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
            resultPtr->setProperty("protocol", "dhcp");
            resultPtr->flags.set(pcapfs::flags::PROCESSED);

            try {
                resultPtr->setFilesizeProcessed(resultPtr->calculateProcessedSize(idx));
            } catch (nlohmann::json_abi_v3_11_3::detail::type_error &err) {
                LOG_ERROR << "Failed to parse DHCP content.";
                offset += udpFrag.length;
                if (offset >= size)
                    break;
                continue;
            }

            if (dhcpLayer.getDhcpHeader()->opCode == 1)
                resultPtr->setFilename("REQ-" + std::to_string(be32toh(dhcpLayer.getDhcpHeader()->transactionID)));
            else
                resultPtr->setFilename("RES-" + std::to_string(be32toh(dhcpLayer.getDhcpHeader()->transactionID)));
            resultVector.push_back(resultPtr);

            offset += udpFrag.length;
            if (offset >= size)
                break;
        }
    }

    return resultVector;
}


bool pcapfs::DhcpFile::isDhcpTraffic(const FilePtr &filePtr) {
    return filePtr->getProperty("protocol") == "udp" &&
            ((filePtr->getProperty("srcPort") == "67" || filePtr->getProperty("srcPort") == "68"));
}


size_t pcapfs::DhcpFile::calculateProcessedSize(const Index &idx) {
    const Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    const FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    return parseDhcpToJson(rawData).size();
}


std::string const pcapfs::DhcpFile::parseDhcpToJson(Bytes data) {
    pcpp::Packet packet;
    const pcpp::DhcpLayer dhcpLayer(data.data(), data.size(), nullptr, &packet);
    nlohmann::json output_json;
    output_json["ID"] = std::to_string(be32toh(dhcpLayer.getDhcpHeader()->transactionID));
    output_json["Client IP Address"] = dhcpLayer.getClientIpAddress().toString();
    output_json["Your IP Address"] = dhcpLayer.getYourIpAddress().toString();
    output_json["Next Server IP Address"] = dhcpLayer.getServerIpAddress().toString();
    output_json["Relay Agent IP Address"] = dhcpLayer.getGatewayIpAddress().toString();
    output_json["Client MAC Address"] = dhcpLayer.getClientHardwareAddress().toString();
    output_json["Server Host Name"] = rawBytesToString(dhcpLayer.getDhcpHeader()->serverName, 64);
    output_json["Boot File Name"] = rawBytesToString(dhcpLayer.getDhcpHeader()->bootFilename, 128);
    output_json["Options"] = parseDhcpOptions(dhcpLayer);
    return output_json.dump(1, '\t');
}


nlohmann::json const pcapfs::DhcpFile::parseDhcpOptions(const pcpp::DhcpLayer &dhcpLayer) {
    nlohmann::json result;
    uint8_t dhcpMessageType = 0;
    LOG_TRACE << "parsing Dhcp Options";

    pcpp::DhcpOption opt = dhcpLayer.getFirstOptionData();
    while (opt.isNotNull() && opt.getType() != pcpp::DHCPOPT_END) {
         const uint8_t optionType = opt.getType();
         uint8_t* optionValue = opt.getValue();
         LOG_TRACE << "optionType: " << std::to_string(optionType) << " " << dhcpOptions::dhcpOptionStrings.at(optionType);

        if (isInSet(dhcpOptions::typesWithIpAddress, optionType)) {
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = pcpp::IPv4Address(optionValue).toString();

        } else if (isInSet(dhcpOptions::typesWithListOfIpAddresses, optionType)) {
            std::vector<std::string> ipList;
            for (size_t i = 0; i < opt.getDataSize(); i+= 4)
                ipList.push_back(pcpp::IPv4Address(&optionValue[i]).toString());
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = ipList;

        } else if (isInSet(dhcpOptions::typesWithIntValue, optionType)) {
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = be16toh(*(uint16_t*) opt.getValue());

        } else if (isInSet(dhcpOptions::typesWithListOfIntValues, optionType)) {
            std::vector<uint16_t> intList;
            for (size_t i = 0; i < opt.getDataSize(); i+= 2)
                intList.push_back(be16toh(*(uint16_t*) (&optionValue[i])));
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = intList;

        } else if (isInSet(dhcpOptions::typesWithTimeValue, optionType)) {
            std::stringstream ss;
            ss << be32toh(*((uint32_t*) optionValue)) << " seconds";
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = ss.str();

        } else if (isInSet(dhcpOptions::typesWithOneByteValue, optionType)) {
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = opt.getValueAs<uint8_t>();

        } else if (optionType == pcpp::DHCPOPT_DHCP_MESSAGE_TYPE) {
            dhcpMessageType = opt.getValueAs<uint8_t>();
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = dhcpMessageTypes.at(dhcpMessageType);

        } else if (optionType == pcpp::DHCPOPT_DHCP_PARAMETER_REQUEST_LIST) {
            std::vector<std::string> requestList;
            for (size_t i = 0; i < opt.getDataSize(); ++i)
                requestList.push_back(dhcpOptions::dhcpOptionStrings.at(optionValue[i]));
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = requestList;

        } else if (optionType == pcpp::DHCPOPT_FQDN) {
            nlohmann::json entry;
            entry["Flags"] = std::to_string(optionValue[0]);
            entry["A-RR Result"] = std::to_string(optionValue[1]);
            entry["PTR-RR Result"] = std::to_string(optionValue[2]);
            entry["Client Name"] = std::string(&optionValue[3], &optionValue[opt.getDataSize()-1]);
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = entry;

        } else if (optionType == pcpp::DHCPOPT_DHCP_CLIENT_IDENTIFIER) {
            nlohmann::json entry;
            if (optionValue[0] == 1) {
                entry["Hardware Type"] = "Ethernet";
                entry["Client MAC Address"] = pcpp::MacAddress(&optionValue[1]).toString();
            } else {
                entry["Type"] = std::to_string(optionValue[0]);
                if (std::all_of(&optionValue[1], optionValue+opt.getDataSize(), [](uint8_t val){ return std::isprint(val); }))
                    entry["Identifier"] = std::string(&optionValue[1], optionValue+opt.getDataSize());
            }
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = entry;

        } else if (optionType == pcpp::DHCPOPT_AUTHENTICATION) {
            nlohmann::json entry;
            std::stringstream ss;
            ss << std::hex << be64toh(*(uint64_t*) (&optionValue[3]));
            entry["Replay Detection Value"] = "0x" + ss.str();
            if (optionValue[0] == 1) {
                entry["Protocol"] = "delayed authentication";
                entry["Algorithm"] = std::to_string(optionValue[1]);
                entry["Replay Detection Method"] = std::to_string(optionValue[2]);
                if (dhcpMessageType == pcpp::DHCP_OFFER || dhcpMessageType == pcpp::DHCP_REQUEST ||
                    dhcpMessageType == pcpp::DHCP_ACK) {
                    ss.str("");
                    ss << std::hex << be32toh(*(uint32_t*) (&optionValue[11]));
                    entry["Secret ID"] = "0x" + ss.str();
                    ss.str("");
                    ss << std::hex << be64toh(*(uint64_t*) (&optionValue[15])) << be64toh(*(uint64_t*) (&optionValue[23]));
                    entry["HMAC MD5 Hash"] = ss.str();
                }
            } else {
                // Authentication information field missing
                entry["Protocol"] = "configuration token";
            }
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = entry;

        } else if (optionType == pcpp::DHCPOPT_DHCP_AGENT_OPTIONS) {
            nlohmann::json entry;
            std::stringstream ss;
            ss << std::hex;
            const uint8_t subOptLen = optionValue[1];
            for (uint8_t pos = 2; pos < subOptLen + 2; ++pos)
                ss << std::setw(2) << std::setfill('0') << (int)optionValue[pos];
            if (optionValue[0] == 1) {
                entry["Suboption"] = "Agent Circuit ID";
                entry["Circuit ID"] = ss.str();

            } else if (optionValue[0] == 2) {
                entry["Suboption"] = "Agent Remote ID";
                entry["Remote ID"] = ss.str();
            }
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = entry;

        } else if (optionType == pcpp::DHCPOPT_SIP_SERVERS) {
            nlohmann::json entry;
            if (optionValue[0] == 1) {
                entry["Encoding"] = "IPv4 Address";
                std::vector<std::string> ipList;
                for (size_t i = 1; i < opt.getDataSize(); i+= 4)
                    ipList.push_back(pcpp::IPv4Address(&optionValue[i]).toString());
                entry["Addresses"] = ipList;
            } else if (optionValue[0] == 0) {
                entry["Encoding"] = "Domain Name";
                entry["Domain Names"] = std::string(&optionValue[1], &optionValue[opt.getDataSize()-1]);
            }
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = entry;

        } else if (std::all_of(optionValue, optionValue+opt.getDataSize()-1, [](uint8_t val){ return std::isprint(val); })) {
                if (optionValue[opt.getDataSize()-1] == 0x00)
                    result[dhcpOptions::dhcpOptionStrings.at(optionType)] = rawBytesToString(optionValue, opt.getDataSize());
                else
                    result[dhcpOptions::dhcpOptionStrings.at(optionType)] = opt.getValueAsString();
        } else {
            result[dhcpOptions::dhcpOptionStrings.at(optionType)] = "";
        }

        opt = dhcpLayer.getNextOptionData(opt);
    }
    return result;
}


std::string const pcapfs::DhcpFile::rawBytesToString(uint8_t* data, size_t len) {
    return std::string(data, std::find_if(data, data+len, [](uint8_t c){ return c == 0x00; }));
}


bool pcapfs::DhcpFile::isInSet(const std::set<uint8_t> &set, uint8_t val) {
    return std::find(set.begin(), set.end(), val) != set.end();
}


size_t pcapfs::DhcpFile::read(uint64_t startOffset, size_t length, const Index &idx, char *buf) {
    const Fragment fragment = fragments.at(0);
    Bytes rawData(fragment.length);
    const FilePtr filePtr = idx.get({offsetType, fragment.id});
    filePtr->read(0 + fragment.start, fragment.length, idx, reinterpret_cast<char *>(rawData.data()));
    const std::string output_string = parseDhcpToJson(rawData);
    memcpy(buf, output_string.c_str() + startOffset, length);
    return std::min((size_t) output_string.length() - startOffset, length);
}


bool pcapfs::DhcpFile::registeredAtFactory =
        pcapfs::FileFactory::registerAtFactory("dhcp", pcapfs::DhcpFile::create, pcapfs::DhcpFile::parse);
