#include "ftp_port_bridge.h"

#include <iostream>

namespace pcapfs {
    FTPPortBridge::FTPPortBridge() {}

    /**
     * Add FileTransmissionData to a specific port.
     *
     * @param port
     * @param data
     */
    void FTPPortBridge::addFileTransmissionData(uint16_t port, const FileTransmissionData &data) {
        DataMap::iterator it = data_transmissions.find(port);

        if (it == data_transmissions.end()) {
            std::vector<FileTransmissionData> files;
            files.emplace_back(data);
            data_transmissions.insert(DataMapPair(port, files));

        } else {
            it->second.emplace_back(data);
        }

    }

    /**
     * Get transmission files data for a specific port.
     *
     * @param port
     * @return
     */
    std::vector<FileTransmissionData> FTPPortBridge::getFileTransmissionData(uint16_t port) {
        DataMap::iterator it = data_transmissions.find(port);

        if (it != data_transmissions.end()) {
            return it->second;
        } else {
            return std::vector<FileTransmissionData>(0);
        }
    }
}
