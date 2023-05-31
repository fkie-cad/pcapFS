#ifndef PCAPFS_CS_CALLBACK_CODES_H
#define PCAPFS_CS_CALLBACK_CODES_H

#include <string>

namespace pcapfs {
    class CSCallback {
    public:
        static const std::vector<std::string> codes;
    };
}

const std::vector<std::string> pcapfs::CSCallback::codes = {
                "CALLBACK_OUTPUT",
                "CALLBACK_KEYSTROKES",
                "CALLBACK_FILE",
                "CALLBACK_SCREENSHOT",
                "CALLBACK_CLOSE",
                "CALLBACK_READ",
                "CALLBACK_CONNECT",
                "CALLBACK_PING",
                "CALLBACK_FILE_WRITE",
                "CALLBACK_FILE_CLOSE",
                "CALLBACK_PIPE_OPEN",
                "CALLBACK_PIPE_CLOSE",
                "CALLBACK_PIPE_READ",
                "CALLBACK_POST_ERROR",
                "CALLBACK_PIPE_PING",
                "CALLBACK_TOKEN_STOLEN",
                "CALLBACK_TOKEN_GETUID",
                "CALLBACK_PROCESS_LIST",
                "CALLBACK_POST_REPLAY_ERROR",
                "CALLBACK_PWD",
                "CALLBACK_JOBS",
                "CALLBACK_HASHDUMP",
                "CALLBACK_PENDING",
                "CALLBACK_ACCEPT",
                "CALLBACK_NETVIEW",
                "CALLBACK_PORTSCAN",
                "CALLBACK_DEAD",
                "CALLBACK_SSH_STATUS",
                "CALLBACK_CHUNK_ALLOCATE",
                "CALLBACK_CHUNK_SEND",
                "CALLBACK_OUTPUT_OEM",
                "CALLBACK_ERROR",
                "CALLBACK_OUTPUT_UTF8"
};

#endif // PCAPFS_CS_CALLBACK_CODES_H
