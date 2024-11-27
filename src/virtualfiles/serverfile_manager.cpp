#include  "serverfile_manager.h"

uint64_t pcapfs::ServerFileManager::getNewId() {
    const uint64_t newId = idCounter;
    idCounter++;
    return newId;
}