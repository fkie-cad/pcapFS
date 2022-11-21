
#ifndef PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H
#define PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H

#include "../commontypes.h"
#include <pcapplusplus/SSLLayer.h>
#include <string>
#include <iostream>
/**
 * @todo write docs
 */
namespace pcapfs {

	class CipherTextElement {
	public:
		//CipherTextElement();

		//~CipherTextElement();

		std::string cipherSuite = "";
		uint16_t sslVersion = 0;
		size_t length = 0;
		uint64_t virtual_file_offset = 0;

		bool isClientBlock;
		Bytes cipherBlock;
		Bytes keyMaterial;

		void printMe(void);
	};

}
#endif // PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H
