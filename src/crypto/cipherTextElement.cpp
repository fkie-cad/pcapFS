#include "cipherTextElement.h"
#include <iostream>
#include <cstdio>
#include "../logging.h"

void pcapfs::CipherTextElement::printMe(void) {
    
	LOG_INFO << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
	LOG_INFO << "CIPHER BLOCK SIZE: " << cipherBlock.size() << std::endl;
    
    for(size_t j=0; j<cipherBlock.size(); j++) {
        if(j%16==0) printf("\n");
        printf("%02x ", (int) cipherBlock.at(j));
    }
    LOG_INFO  << std::endl;
    
    
}
