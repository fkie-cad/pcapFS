#include "cipherTextElement.h"
#include <iostream>
#include <cstdio>

void CipherTextElement::printMe(void) {
    std::cout  << std::endl;
    
    std::cout << (isClientBlock ? "CLIENT" : "SERVER") << std::endl;
    
    std::cout << "CIPHER BLOCK SIZE: " << cipherBlock.size() << std::endl;
    
    for(int j=0; j<cipherBlock.size(); j++) {
        if(j%16==0) printf("\n");
        printf("%x ", (int) cipherBlock.at(j));
    }
    std::cout  << std::endl;
    
    
}
