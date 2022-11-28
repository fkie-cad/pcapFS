#include "plainTextElement.h"
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include "../logging.h"

#include <openssl/err.h>


void pcapfs::PlainTextElement::printMe(void) {
    
	LOG_INFO << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
	LOG_INFO << "PLAIN TEXT BLOCK SIZE: " << plaintextBlock.size() << std::endl;
    
    printf("plain block:\n");
    BIO_dump_fp (stdout, (const char *)plaintextBlock.data(), plaintextBlock.size());

    //printf("hmac block:\n");
    //BIO_dump_fp (stdout, (const char *)hmac.data(), hmac.size());

}
