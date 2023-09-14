#include "smb_messages.h"
#include "smb_headers.h"


pcapfs::smb::SmbPacket::SmbPacket(const uint8_t* data, size_t len) {
    if (len < 64)
        throw PcapFsException("Invalid SMB Packet Header");
    memcpy(&header, data, 64);
    if (header.protocolId != 0x424D53FE)
        throw PcapFsException("Invalid SMB Packet Header");
    isResponse = header.flags & SMB2_FLAGS_SERVER_TO_REDIR;
    if (isResponse && (header.status != STATUS_SUCCESS)) {
        try{
            message = ErrorResponse(&data[64], len - 64);
        } catch (const PcapFsException &err) {
            // we don't have a correct Error Response Message and try the other message types in the switch
        }
    }
    try {
        switch (header.command) {
            case SMB2_NEGOTIATE:
                if (isResponse)
                    message = NegotiateResponse(&data[64], len - 64);
                else 
                    message = NegotiateRequest(&data[64], len - 64);
                break;
            
            case SMB2_QUERY_INFO:
                if (isResponse)
                    // TODO: change to QueryInfoResponse
                    message = SmbMessage(&data[64], len - 64);
                else 
                    message = QueryInfoRequest(&data[64], len - 64);
                break;

            default:
                message = SmbMessage(&data[64], len - 64);
        }
    } catch (const PcapFsException &err) {
        message = SmbMessage(&data[64], len - 64);
    }
    command = commandToString(header.command);
    size = 64 + message.totalSize;
}


std::string const pcapfs::smb::SmbPacket::commandToString(uint16_t cmdCode) {
    std::string result = cmdCode <= 0x12 ? smbCommandStrings[cmdCode] : "SMB2 UNKNOWN";
    result.append(isResponse ? " Response" : " Request");
    return result;
}

