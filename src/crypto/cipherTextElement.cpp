#include "cipherTextElement.h"
#include <iostream>
#include <cstdio>
#include "../logging.h"

#include <openssl/err.h>


void pcapfs::CipherTextElement::printMe(void) {
    
	LOG_INFO << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
	LOG_INFO << "CIPHER BLOCK SIZE: " << cipherBlock.size() << std::endl;
    
    printf("plain block:\n");
    BIO_dump_fp (stdout, (const char *)cipherBlock.data(), cipherBlock.size());
    
    
}