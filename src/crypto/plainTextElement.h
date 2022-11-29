#ifndef PCAPFS_CRYPTO_PLAINTEXTELEMENT_H
#define PCAPFS_CRYPTO_PLAINTEXTELEMENT_H

#include <string>
#include "../commontypes.h"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLLayer.h>
#include <string>
#include <iostream>

/**
 * @todo write docs
 */
namespace pcapfs {

	class PlainTextElement {
	public:
		//PlainTextElement();

		//~PlainTextElement();

		uint16_t getVirtualFileOffset() { return virtualFileOffset; };
		std::string const &getCipherSuite() { return cipherSuite; };
		uint16_t getSslVersion(){ return sslVersion; };
		Bytes const &getPlaintextBlock(){ return plaintextBlock; };
		//Bytes const &getHmac(){ return hmac; };
		uint64_t getPadding(){ return padding; };
		
		void setVirtualFileOffset(const uint16_t offset) { virtualFileOffset = offset; };
		void setCipherSuite(const std::string &cipherSuite) { this->cipherSuite = cipherSuite; };
		void setSslVersion(const uint16_t sslVersion) { this->sslVersion = sslVersion; };
		void setPlaintextBlock(const Bytes& newPlaintextBlock) { plaintextBlock = newPlaintextBlock; };
		//void setHmac(const Bytes& newHmac) { hmac = newHmac; };
		void setPadding(const uint64_t pad) { padding = pad; };

		bool isClientBlock;

		void printMe(void);
	
	private:
		Bytes plaintextBlock;
		//Bytes hmac;
		uint64_t virtualFileOffset;

		uint64_t padding;

		uint16_t sslVersion;
		std::string cipherSuite;

	};

}
#endif // PCAPFS_CRYPTO_PLAINTEXTELEMENT_H
