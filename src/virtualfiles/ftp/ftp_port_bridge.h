#ifndef PCAPFS_FTP_BRIDGE_H
#define PCAPFS_FTP_BRIDGE_H

#include <cstdint>
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "ftp_commands.h"
#include "../ftpcontrol.h"
#include "../../commontypes.h"

#include <iostream>


namespace pcapfs {
    struct FileTransmissionData {
        std::string transmission_file;
        std::string transmission_type;
        TimeSlot time_slot;
    };

    class FTPPortBridge {
    private:
        std::map<uint16_t, std::vector<FileTransmissionData>> data_transmissions;

    public:
        using DataMap = std::map<uint16_t, std::vector<FileTransmissionData>>;
        using DataMapPair = std::pair<uint16_t, std::vector<FileTransmissionData>>;

        static FTPPortBridge &getInstance() {
            static FTPPortBridge instance;
            return instance;
        }

        FTPPortBridge(const FTPPortBridge &) = delete;

        FTPPortBridge(FTPPortBridge &&) = delete;

        void operator=(const FTPPortBridge &) = delete;

        void addFileTransmissionData(uint16_t port, const FileTransmissionData &data);

        std::vector<FileTransmissionData> getFileTransmissionData(uint16_t port);

    private:
        FTPPortBridge();
    };
}

#endif
