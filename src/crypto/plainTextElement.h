#ifndef PLAINTEXTELEMENT_H
#define PLAINTEXTELEMENT_H

/**
 * @todo write docs
 */
class PlainTextElement
{
public:
    pcapfs::Bytes plaintextBlock;
    bool isClientBlock;
    int plainTextLength;
    int paddingLength;
    int hmacLength;
    
    int beginEncryptedText;
    int endEncryptedText;
    
    int beginHmac;
    int endHmac;
    
    int beginPaddingBytes;
    int endPaddingBytes;
    
    pcpp::SSLVersion sslVersion;
    std::string cipherSuite;
};

#endif // PLAINTEXTELEMENT_H
