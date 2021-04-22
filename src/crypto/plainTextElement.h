#ifndef PLAINTEXTELEMENT_H
#define PLAINTEXTELEMENT_H

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

	class PlainTextElement
	{
	public:
		pcapfs::Bytes plaintextBlock;
		pcapfs::Bytes hmac;
		int padding;

		bool isClientBlock;

		uint16_t sslVersion;
		std::string cipherSuite;

		void printMe(void);
	};

}
#endif // PLAINTEXTELEMENT_H
