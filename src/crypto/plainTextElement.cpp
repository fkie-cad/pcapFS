#include "plainTextElement.h"
#include <iostream>
#include <cstdio>

void PlainTextElement::printMe(void) {
    std::cout  << std::endl;
    
    std::cout << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
    std::cout << "PLAIN TEXT BLOCK SIZE: " << plaintextBlock.size() << std::endl;
    
    for(size_t j=0; j<plaintextBlock.size(); j++) {
        if(j%16==0) printf("\n");
        printf("%x ", (int) plaintextBlock.at(j));
    }
    std::cout  << std::endl;
}
