#ifndef PCAPFS_CRYPTO_PLAINTEXTELEMENT_H
#define PCAPFS_CRYPTO_PLAINTEXTELEMENT_H

#include "../commontypes.h"

/**
 * @todo write docs
 */
namespace pcapfs {

	class PlainTextElement {
	public:
		//PlainTextElement();

		//~PlainTextElement();

		Bytes const &getPlaintextBlock(){ return plaintextBlock; };	
		void setPlaintextBlock(const Bytes& newPlaintextBlock) { plaintextBlock = newPlaintextBlock; };

		void printMe(void);
	
	private:
		Bytes plaintextBlock;
	};

}

#endif // PCAPFS_CRYPTO_PLAINTEXTELEMENT_H
