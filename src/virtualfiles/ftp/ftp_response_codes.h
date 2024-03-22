#ifndef PCAPFS_FTP_RESPONSE_CODES_H
#define PCAPFS_FTP_RESPONSE_CODES_H

#include <cstdint>

namespace pcapfs {
	struct FTPResponseCodes {
		enum Codes : uint16_t {
			OK = 200,
			FileStatusOK = 150,
			ClosingDataConnection = 226,
			EnteringPassiveMode = 227,
			EnteringExtendedPassiveMode = 229,
			ClosingControlConnection = 421,
			FileActionSuccessful = 250
		};
	};
}

#endif
