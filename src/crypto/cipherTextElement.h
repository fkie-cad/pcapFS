#include "../commontypes.h"
#include <pcapplusplus/SSLLayer.h>

#ifndef CIPHERTEXTELEMENT_H
#define CIPHERTEXTELEMENT_H

/**
 * @todo write docs
 */
class CipherTextElement
{
public:
    std::string cipherSuite;
    pcpp::SSLVersion sslVersion;
    int length;
    
    bool isClientBlock;
    pcapfs::Bytes cipherBlock;
    pcapfs::Bytes keyMaterial;
};

#endif // CIPHERTEXTELEMENT_H
