#ifndef PCAPFS_FTP_COMMANDS_H
#define PCAPFS_FTP_COMMANDS_H

#include <string>

namespace pcapfs {
	class FTPCommands {
		public:
			static const std::string ALLO; // Allocate sufficient disk space to receive a file.
			static const std::string AUTH; // authentication mechanism: AUTH TLS
			static const std::string FEAT; // Get the feature list implemented by the server.
			static const std::string LIST; // list files
			static const std::string MFMT; // modify last modification info of a file
			static const std::string MKD; // make directory
			static const std::string MLSD; // list directory content
			static const std::string PASS; // passwort for authentication
			static const std::string PASV; // enter passive mode
			static const std::string PORT; // Specifies an address and port to which the server should connect.
			static const std::string PWD;
			static const std::string RETR; // Retrieve a copy of the file
			static const std::string STOR; // Accept the data and to store the data as a file at the server site
			static const std::string TYPE; // set the transfer mode
			static const std::string USER; // user name for authentication
			static const std::string QUIT;
	};
}

#endif
