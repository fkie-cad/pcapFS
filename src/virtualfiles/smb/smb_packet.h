#ifndef PCAPFS_SMB_PACKET_H
#define PCAPFS_SMB_PACKET_H

#include "smb_constants.h"
#include "smb_structs.h"
#include "smb_messages.h"


namespace pcapfs {
    namespace smb {

        class SmbPacket {
        public:
            SmbPacket() {};
            SmbPacket(const uint8_t* data, size_t len, SmbContextPtr &smbContext);

            std::string const toString(const SmbContextPtr &smbContext);

            std::shared_ptr<SmbHeader> header = nullptr;
            std::shared_ptr<SmbMessage> message;
            size_t size = 0;
            bool isResponse = false;
            bool isErrorResponse = false;
            bool parsingFailed = false;
            uint8_t headerType = HeaderType::SMB2_PACKET_HEADER;

        private:
            std::string const smb1CommandToString(uint8_t cmdCode);
            std::string const smb2CommandToString(uint16_t cmdCode);
        };
    }
}

#endif //PCAPFS_SMB_PACKET_H
