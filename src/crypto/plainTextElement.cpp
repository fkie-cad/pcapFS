#include "plainTextElement.h"
#include <fstream>
#include <iostream>
#include <string>
#include <cstdio>
#include "../logging.h"


void pcapfs::PlainTextElement::printMe(void) {
    
	LOG_INFO << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
	LOG_INFO << "PLAIN TEXT BLOCK SIZE: " << plaintextBlock.size() << std::endl;
    
    for(size_t j=0; j<plaintextBlock.size(); j++) {
        if(j%16==0) printf("\n");
        printf("%02x ", (int) plaintextBlock.at(j));
    }
    LOG_INFO  << std::endl;
}
