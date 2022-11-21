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

		pcapfs::Bytes plaintextBlock;
		pcapfs::Bytes hmac;
		uint64_t virtual_file_offset;

		uint64_t padding;

		bool isClientBlock;

		uint16_t sslVersion;
		std::string cipherSuite;

		void printMe(void);
	};

}
#endif // PCAPFS_CRYPTO_PLAINTEXTELEMENT_H
