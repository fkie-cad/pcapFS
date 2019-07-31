#ifndef PLAINTEXTELEMENT_H
#define PLAINTEXTELEMENT_H

/**
 * @todo write docs
 */
class PlainTextElement
{
public:
    pcapfs::Bytes plaintextBlock;;
    bool isClientBlock;;
    int length;;
    pcpp::SSLVersion sslVersion;;
    std::string cipherSuite;;
};

#endif // PLAINTEXTELEMENT_H
