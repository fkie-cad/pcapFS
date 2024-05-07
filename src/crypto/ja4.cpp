#include "ja4.h"
#include "cryptutils.h"



std::string const pcapfs::ja4::extractTlsVersion(pcpp::SSLExtension* supportedVersions, uint16_t tlsVersion) {
    if (supportedVersions) {
        pcpp::SSLVersion::SSLVersionEnum maxSupportedVersion = pcpp::SSLVersion::Unknown;
    const pcpp::SSLSupportedVersionsExtension* supportedVersionsExtension = dynamic_cast<pcpp::SSLSupportedVersionsExtension*>(supportedVersions);
    for (auto entry : supportedVersionsExtension->getSupportedVersions()) {
        if (tlsGreaseValues.find(entry.asUInt()) == tlsGreaseValues.end() && entry.asEnum() > maxSupportedVersion)
            maxSupportedVersion = entry.asEnum();
    }
    if (tlsVersionMap.count(maxSupportedVersion))
        return tlsVersionMap.at(maxSupportedVersion);
    else
        return "00";
    } else {
        if (tlsVersionMap.count(tlsVersion))
            return tlsVersionMap.at(tlsVersion);
        else
            return "00";
    }
}



std::string const pcapfs::ja4::extractAlpn(pcpp::SSLExtension* alpn) {
    if (alpn && alpn->getLength() > 2) {
        const Bytes rawAlpnData(alpn->getData(), alpn->getData()+alpn->getLength());
        const uint8_t firstEntryLength = rawAlpnData.at(2);
        if (firstEntryLength > rawAlpnData.size() - 3 || firstEntryLength < 2) {
            return "00";
        } else {
            if (firstEntryLength == 2) {
                return std::string(rawAlpnData.begin()+3, rawAlpnData.begin()+3+firstEntryLength);
            } else {
                // alpn string is longer than 2 => take first and last character
                // (e.g., "http/1.1" -> "h1")
                return std::string(rawAlpnData.begin()+3, rawAlpnData.begin()+4) +
                        std::string(rawAlpnData.begin()+3+firstEntryLength-1, rawAlpnData.begin()+3+firstEntryLength);
            }
        }
    } else {
        return "00";
    }
}



std::string const pcapfs::ja4::getAsCommaSeparatedString(const std::vector<uint16_t> &values) {
    std::stringstream ss;
    for (uint16_t i = 0; i < values.size(); ++i) {
        ss << std::setw(4) << std::setfill('0') << std::hex << values.at(i);
        if (i != values.size() -1)
            ss << ",";
    }
    return ss.str();
}



std::string const pcapfs::ja4::getAsHashOfCommaSeparatedString(const std::vector<uint16_t> &values) {
    const std::string list = getAsCommaSeparatedString(values);
    return getAsHashPart(list);
}



std::string const pcapfs::ja4::getAsHashPart(const std::string &input) {
    const std::string hash = crypto::calculateSha256AsString(input);
    if (hash != "")
        return std::string(hash.begin(), hash.begin()+12);
    else
        return "000000000000";
}



std::string const pcapfs::ja4::calculateJa4(const pcpp::SSLClientHelloMessage::ClientHelloTLSFingerprint& fingerprint, const std::string &sni,
                                                 pcpp::SSLExtension* alpn, pcpp::SSLExtension* signatureAlgorithms, pcpp::SSLExtension* supportedVersions) {
    // fingerprint begins with t for TCP, we don't support QUIC
    std::string ja4 = "t";
    ja4 += extractTlsVersion(supportedVersions, fingerprint.tlsVersion);
    ja4 += (sni != "") ? "d" : "i";

    const size_t numCipherSuites = fingerprint.cipherSuites.size();
    ja4 += numCipherSuites < 10 ? "0" + std::to_string(numCipherSuites) : std::to_string(numCipherSuites);

    const size_t numExtensions = fingerprint.extensions.size();
    ja4 += numExtensions < 10 ? "0" + std::to_string(numExtensions) : std::to_string(numExtensions);

    ja4 += extractAlpn(alpn);
    ja4 += "_";

    std::vector<uint16_t> cipherSuites = fingerprint.cipherSuites;
    std::sort(cipherSuites.begin(), cipherSuites.end());
    ja4 += getAsHashOfCommaSeparatedString(cipherSuites);
    ja4 += "_";

    // neglect sni and alpn extension
    std::vector<uint16_t> tmpVector = fingerprint.extensions;
    tmpVector.erase(std::remove(tmpVector.begin(), tmpVector.end(), 0), tmpVector.end());
    tmpVector.erase(std::remove(tmpVector.begin(), tmpVector.end(), 16), tmpVector.end());
    std::sort(tmpVector.begin(), tmpVector.end());
    std::string formattedExtensionsList = getAsCommaSeparatedString(tmpVector);

    if (signatureAlgorithms) {
        const Bytes rawSignAlgosData(signatureAlgorithms->getData()+2, signatureAlgorithms->getData()+signatureAlgorithms->getLength());
        std::stringstream ss;
        for (uint16_t i = 0; i < rawSignAlgosData.size(); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)rawSignAlgosData.at(i);
            if (i % 2 != 0 && i != rawSignAlgosData.size() -1)
                ss << ",";
        }
        formattedExtensionsList += "_" + ss.str();
    }

    ja4 += getAsHashPart(formattedExtensionsList);

    return ja4;
}



std::string const pcapfs::ja4::calculateJa4S(const pcpp::SSLServerHelloMessage::ServerHelloTLSFingerprint& fingerprint, pcpp::SSLExtension* alpn,
                                                pcpp::SSLExtension* supportedVersions) {
    // fingerprint begins with t for TCP, we don't support QUIC
    std::string ja4s = "t";
    ja4s += extractTlsVersion(supportedVersions, fingerprint.tlsVersion);
    const size_t numExtensions = fingerprint.extensions.size();
    ja4s += numExtensions < 10 ? "0" + std::to_string(numExtensions) : std::to_string(numExtensions);
    ja4s += extractAlpn(alpn);
    ja4s += "_";

    std::stringstream ss;
    ss << std::setw(4) << std::setfill('0') << std::hex << fingerprint.cipherSuite;
    ja4s += ss.str();
    ja4s += "_";

    // (for JA4S, the extensions list is not sorted)
    ja4s += getAsHashOfCommaSeparatedString(fingerprint.extensions);
    
    return ja4s;
}