
#ifndef CIPHERTEXTELEMENT_H
#define CIPHERTEXTELEMENT_H

#include "../commontypes.h"
#include <pcapplusplus/SSLLayer.h>
#include <string>
/**
 * @todo write docs
 */
namespace pcapfs {

	class CipherTextElement
	{
	public:
		std::string cipherSuite;
		pcpp::SSLVersion sslVersion;
		int length;
		int padding;

		bool isClientBlock;
		pcapfs::Bytes cipherBlock;
		pcapfs::Bytes keyMaterial;

		void printMe(void);
	};

}
#endif // CIPHERTEXTELEMENT_H
