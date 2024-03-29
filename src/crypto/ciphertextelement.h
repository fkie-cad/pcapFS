
#ifndef PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H
#define PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H

#include "../commontypes.h"

#include <memory>

namespace pcapfs {

	class CipherTextElement {
	public:

		size_t getLength() { return length; };
		uint64_t getVirtualFileOffset(){ return virtualFileOffset; };
		Bytes const &getCipherBlock(){ return cipherBlock; };
		Bytes const &getKeyMaterial(){ return keyMaterial; };

		void setLength(const size_t length) { this->length = length; };
		void setVirtualFileOffset(const uint64_t offset) {this->virtualFileOffset = offset; };
		void setCipherBlock(const Bytes& newCipherBlock) { cipherBlock = newCipherBlock; };
		void setKeyMaterial(const Bytes& newKeyMaterial) { keyMaterial = newKeyMaterial; };

		void printMe(void);

		bool isClientBlock;
		bool encryptThenMacEnabled;
		bool truncatedHmacEnabled;

	private:
		size_t length = 0;
		uint64_t virtualFileOffset = 0;
		Bytes cipherBlock;
		Bytes keyMaterial;
	};

	typedef std::shared_ptr<CipherTextElement> CiphertextPtr;
}
#endif // PCAPFS_CRYPTO_CIPHERTEXTELEMENT_H
