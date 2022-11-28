
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

		std::string const &getCipherSuite() { return cipherSuite; };
		uint16_t const getSslVersion() { return sslVersion; };
		size_t const getLength() { return length; };
		uint64_t const getVirtualFileOffset(){ return virtualFileOffset; };
		Bytes const &getCipherBlock(){ return cipherBlock; };
		Bytes const &getKeyMaterial(){ return keyMaterial; };

		void setCipherSuite(const std::string &cipherSuite) { this->cipherSuite = cipherSuite; };
		void setSslVersion(const uint16_t sslVersion) { this->sslVersion = sslVersion; };
		void setLength(const size_t length) { this->length = length; };
		void setVirtualFileOffset(const uint64_t offset) {this->virtualFileOffset = offset; };
		void setCipherBlock(const Bytes& newCipherBlock) { cipherBlock = newCipherBlock; };
		void setKeyMaterial(const Bytes& newKeyMaterial) { keyMaterial = newKeyMaterial; };

		void printMe(void);

		bool isClientBlock;
		

	private:
		std::string cipherSuite = "";
		uint16_t sslVersion = 0;
		size_t length = 0;
		uint64_t virtualFileOffset = 0;

		Bytes cipherBlock;
		Bytes keyMaterial;
	};


}
#endif // PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H
