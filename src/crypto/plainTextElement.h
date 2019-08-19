#ifndef PLAINTEXTELEMENT_H
#define PLAINTEXTELEMENT_H

#include <string>
#include "../commontypes.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLLayer.h>
#include <string>

/**
 * @todo write docs
 */
class PlainTextElement
{
public:
    pcapfs::Bytes plaintextBlock;
    pcapfs::Bytes hmac;
    pcapfs::Bytes padding;
    
    bool isClientBlock;
    
    pcpp::SSLVersion sslVersion;
    std::string cipherSuite;
    
    void printMe(void);
};

#endif // PLAINTEXTELEMENT_H
