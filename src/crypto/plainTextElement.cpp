#include "plainTextElement.h"
#include "../logging.h"
#include <openssl/err.h>


void pcapfs::PlainTextElement::printMe(void) {
    
	LOG_INFO << "PLAIN TEXT BLOCK SIZE: " << plaintextBlock.size() << std::endl;
    
    printf("plain block:\n");
    BIO_dump_fp (stdout, (const char *)plaintextBlock.data(), plaintextBlock.size());
}
