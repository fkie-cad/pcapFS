#ifndef PCAPFS_SMB_MESSAGES_H
#define PCAPFS_SMB_MESSAGES_H

#include "smb_constants.h"
#include "smb_structs.h"
#include "smb_utils.h"
#include <set>


namespace pcapfs {
    namespace smb {

        class SmbMessage {
        public:
            explicit SmbMessage(size_t len) : totalSize(len) {};
            size_t totalSize = 0;
        };


        class ErrorResponse : public SmbMessage {
        public:
            ErrorResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Error Response");

                const uint32_t byteCount = *(uint32_t*) &rawData.at(4);
                if (byteCount > len - 8)
                    throw SmbError("Invalid SMB2 Error Response Message");

                if (byteCount == 0)
                    totalSize = 9;
                else
                    totalSize = 8 + byteCount;

                LOG_TRACE << "parsed error response";
            }
        };


        class NegotiateRequest : public SmbMessage {
        public:
            NegotiateRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 36)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Negotiate Request");

                const uint16_t dialectCount = *(uint16_t*) &rawData.at(2);
                if (dialectCount > 5 || (size_t)(2*dialectCount + 36) > len)
                    throw SmbError("Invalid amount of dialects in SMB2 Negotiate Request");

                if (contains311Dialect(dialectCount, rawData)) {
                    const uint32_t negotiateContextOffset = *(uint32_t*) &rawData.at(28);
                    const uint16_t negotiateContextCount = *(uint32_t*) &rawData.at(32);
                    if ((size_t)(negotiateContextOffset + (8*negotiateContextCount) - 64) > len)
                        throw SmbError("Invalid negotiate context values in SMB2 Negotiate Request");

                    totalSize = calculate311NegotiateMessageLength(rawData, negotiateContextOffset, negotiateContextCount);
                } else {
                    totalSize = 36 + (2*dialectCount);
                }
            }

        private:
            bool contains311Dialect(uint16_t dialectCount, const Bytes &rawData) {
                for (int pos = 36; pos < 36 + (dialectCount*2) ; pos += 2) {
                    if (*(uint16_t*) &rawData.at(pos) == Version::SMB_VERSION_3_1_1)
                        return true;
                }
                return false;
            }
        };


        class NegotiateResponse : public SmbMessage {
        public:
            NegotiateResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 65)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Negotiate Response");

                systemTime = *(uint64_t*) &rawData.at(40);
                dialect = *(uint16_t*) &rawData.at(4);
                if (dialect == Version::SMB_VERSION_3_1_1) {
                    const uint32_t negotiateContextOffset = *(uint32_t*) &rawData.at(60);
                    const uint16_t negotiateContextCount = *(uint32_t*) &rawData.at(6);
                    // each negotiate context is at least 8 bytes long
                    if ((size_t)(negotiateContextOffset + (8*negotiateContextCount)  - 64) > len)
                        throw SmbError("Invalid negotiate context values in SMB2 Negotiate Response");

                    totalSize = calculate311NegotiateMessageLength(rawData, negotiateContextOffset, negotiateContextCount);
                } else {
                    const uint16_t securityBufferOffset = *(uint16_t*) &rawData.at(56);
                    const uint16_t securityBufferLength = *(uint16_t*) &rawData.at(58);
                    if ((size_t)(securityBufferOffset + securityBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Negotiate Response");

                    totalSize = securityBufferLength == 0 ? 65 : (securityBufferOffset + securityBufferLength - 64);
                }
            }
            uint16_t dialect;
            uint64_t systemTime;
        };


        class SessionSetupRequest : public SmbMessage {
        public:
            SessionSetupRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 25)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Session Setup Request");

                const uint16_t securityBufferOffset = *(uint16_t*) &rawData.at(12);
                const uint16_t securityBufferLength = *(uint16_t*) &rawData.at(14);

                if (securityBufferLength == 0)
                    totalSize = 25;
                else {
                    if ((size_t)(securityBufferOffset + securityBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Session Setup Request");
                    totalSize = securityBufferOffset + securityBufferLength - 64;
                }
            }
        };


        class SessionSetupResponse : public SmbMessage {
        public:
            SessionSetupResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Session Setup Response");

                const uint16_t securityBufferOffset = *(uint16_t*) &rawData.at(4);
                const uint16_t securityBufferLength = *(uint16_t*) &rawData.at(6);

                if (securityBufferLength == 0)
                    totalSize = 8;
                else {
                    if ((size_t)(securityBufferOffset + securityBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Session Setup Response");
                    totalSize = securityBufferOffset + securityBufferLength - 64;
                }
            }
        };


        class TreeConnectRequest : public SmbMessage {
        public:
            TreeConnectRequest(const uint8_t* data, size_t len, uint16_t dialect) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Tree Connect Request");

                const uint16_t pathOffset = *(uint16_t*) &rawData.at(4);
                const uint16_t pathLength = *(uint16_t*) &rawData.at(6);
                if ((size_t)(pathOffset + pathLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Tree Connect Request");

                if (pathOffset != 0 && pathLength != 0)
                    pathName = wstrToStr(Bytes(&rawData.at(pathOffset - 64), &rawData.at(pathOffset-64+pathLength-1)));

                const uint16_t flags = *(uint16_t*) &rawData.at(2);
                if (dialect == Version::SMB_VERSION_3_1_1 && (flags & 4)) {
                    // SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
                    const uint32_t treeConnectContextOffset = *(uint32_t*) &rawData.at(8);
                    const uint16_t treeConnectContextCount = *(uint32_t*) &rawData.at(12);
                    if ((size_t)(treeConnectContextOffset + (8*treeConnectContextCount)) > len)
                        throw SmbError("Invalid buffer values in SMB2 Tree Connect Request");

                    if (treeConnectContextOffset == 0 || treeConnectContextCount == 0) {
                        if (pathOffset != 0 && pathLength != 0)
                            totalSize = pathOffset + pathLength - 64;
                        else
                            totalSize = 9;
                    } else {
                        size_t currPos = treeConnectContextOffset;
                        for (size_t i = 0; i < treeConnectContextCount; ++i) {
                            uint16_t dataLength = (*(uint16_t*) &rawData.at(currPos + 2)) + 8;
                            if (dataLength > rawData.size() - currPos)
                                throw PcapFsException("Invalid context values in SMB2 Tree Connect Request");
                            currPos += dataLength;
                        }
                        totalSize = currPos;
                    }
                } else {
                    if (pathOffset != 0 && pathLength != 0)
                        totalSize = pathOffset + pathLength - 64;
                    else
                        totalSize = 9;
                }
            }
            std::string pathName = "";
        };


        class TreeConnectResponse : public SmbMessage {
        public:
            TreeConnectResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 16)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Tree Connect Response");

                totalSize = 16;
            }
        };


        class CreateRequest : public SmbMessage {
        public:
            CreateRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 57)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Create Request");

                const uint16_t nameOffset = *(uint16_t*) &rawData.at(44);
                const uint16_t nameLength = *(uint16_t*) &rawData.at(46);
                const uint32_t createContextsOffset = *(uint32_t*) &rawData.at(48);
                const uint32_t createContextsLength = *(uint32_t*) &rawData.at(52);

                if (createContextsOffset == 0 && createContextsLength == 0) {
                    if (nameOffset != 0 && nameLength != 0) {
                        if ((size_t)(nameOffset + nameLength - 64) > len)
                            throw SmbError("Invalid buffer values in SMB2 Create Request");

                        totalSize = nameOffset + nameLength - 64;
                        filename = wstrToStr(Bytes(&rawData.at(nameOffset - 64), &rawData.at(nameOffset - 64 + nameLength - 1)));
                    } else {
                        totalSize = 57;
                    }
                } else if (createContextsOffset != 0 && createContextsLength != 0) {
                    if ((size_t)(createContextsOffset + createContextsLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Create Request");

                    totalSize = createContextsOffset + createContextsLength - 64;
                    if (nameOffset != 0 && nameLength != 0) {
                        if ((size_t)(nameOffset + nameLength - 64) > len)
                            throw SmbError("Invalid buffer values in SMB2 Create Request");
                        filename = wstrToStr(Bytes(&rawData.at(nameOffset - 64), &rawData.at(nameOffset - 64 + nameLength - 1)));
                        filename = sanitizeFilename(filename);
                    }
                } else {
                    totalSize = 57;
                }

                const uint32_t extractedDisposition = *(uint32_t*) &rawData.at(36);
                disposition = extractedDisposition <= 5 ? extractedDisposition : CreateDisposition::DISPOSITION_UNKNOWN;
            }
            std::string filename = "";
            uint32_t disposition = CreateDisposition::DISPOSITION_UNKNOWN;
        };


        class CreateResponse : public SmbMessage {
        public:
            CreateResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 89)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Create Response");

                const uint32_t createContextsOffset = *(uint32_t*) &rawData.at(80);
                const uint32_t createContextsLength = *(uint32_t*) &rawData.at(84);

                if (createContextsOffset == 0 && createContextsLength == 0)
                    totalSize = 88;
                else {
                    if ((size_t)(createContextsOffset + createContextsLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Create Response");
                    totalSize = createContextsOffset + createContextsLength - 64;
                }

                const uint32_t extractedAction = *(uint32_t*) &rawData.at(4);
                createAction = extractedAction <= 3 ? extractedAction : CreateAction::ACTION_UNKNOWN;
                fileId = bytesToHexString(Bytes(&rawData.at(64), &rawData.at(80)));

                const uint32_t extractedFileAttributes = *(uint32_t*) &rawData.at(56);
                metaData->isDirectory = extractedFileAttributes & 0x10;
                metaData->creationTime = *(uint64_t*) &rawData.at(8);
                metaData->lastAccessTime = *(uint64_t*) &rawData.at(16);
                metaData->lastWriteTime = *(uint64_t*) &rawData.at(24);
                metaData->changeTime = *(uint64_t*) &rawData.at(32);
            }
            uint32_t createAction = CreateAction::ACTION_UNKNOWN;
            std::string fileId = "";
            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
        };


        class CloseRequest : public SmbMessage {
        public:
            CloseRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 24)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Close Request");

                totalSize = 24;
                fileId = bytesToHexString(Bytes(&rawData.at(8), &rawData[24]));
                postqueryAttrib = (*(uint16_t*) &rawData.at(2) == 1);
            }
            std::string fileId = "";
            bool postqueryAttrib = false;
        };


        class CloseResponse : public SmbMessage {
        public:
            CloseResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 60)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Close Response");

                totalSize = 60;
                if (*(uint16_t*) &rawData.at(2) == 1) {
                    // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB is set
                    postqueryAttrib = true;
                    metaData->creationTime = *(uint64_t*) &rawData.at(8);
                    metaData->lastAccessTime = *(uint64_t*) &rawData.at(16);
                    metaData->lastWriteTime = *(uint64_t*) &rawData.at(24);
                    metaData->changeTime = *(uint64_t*) &rawData.at(32);
                }
            }

            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
            bool postqueryAttrib = false;
        };


        class FlushRequest : public SmbMessage {
        public:
            FlushRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 24)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Flush Request");

                totalSize = 24;
            }
        };


        class ReadRequest : public SmbMessage {
        public:
            ReadRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 49)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Read Request");

                const uint16_t readChannelInfoOffset = *(uint16_t*) &rawData.at(44);
                const uint16_t readChannelInfoLength = *(uint16_t*) &rawData.at(46);

                if (readChannelInfoOffset == 0 && readChannelInfoLength == 0)
                    totalSize = 49;
                else {
                    if ((size_t)(readChannelInfoOffset + readChannelInfoLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Read Request");
                    totalSize = readChannelInfoOffset + readChannelInfoLength - 64;
                }
                fileId = bytesToHexString(Bytes(&rawData.at(16), &rawData.at(32)));
                readOffset = *(uint64_t*) &rawData.at(8);
                readLength = *(uint32_t*) &rawData.at(4);
            }
            std::string fileId = "";
            uint64_t readOffset = 0;
            uint32_t readLength = 0;
        };


        class ReadResponse : public SmbMessage {
        public:
            ReadResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 17)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Read Response");

                dataOffset = rawData.at(2);
                dataLength = *(uint32_t*) &rawData.at(4);

                if (dataOffset == 0 && dataLength == 0)
                    totalSize = 17;
                else {
                    if ((size_t)(dataOffset + dataLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Read Response");
                    totalSize = dataOffset + dataLength - 64;
                }
            }

            uint8_t dataOffset = 0;
            uint32_t dataLength = 0;
        };


        class WriteRequest : public SmbMessage {
        public:
            WriteRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 49)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Write Request");

                dataOffset = *(uint16_t*) &rawData.at(2);
                writeLength = *(uint32_t*) &rawData.at(4);
                const uint16_t writeChannelInfoOffset = *(uint16_t*) &rawData.at(40);
                const uint16_t writeChannelInfoLength = *(uint16_t*) &rawData.at(42);

                if (dataOffset == 0 && writeLength == 0 && writeChannelInfoOffset == 0 && writeChannelInfoLength == 0)
                    totalSize = 49;
                else if (writeChannelInfoOffset == 0 && writeChannelInfoLength == 0) {
                    if ((size_t)(dataOffset + writeLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Write Request");
                    totalSize = dataOffset + writeLength - 64;
                } else {
                    if ((size_t)(writeChannelInfoOffset + writeChannelInfoLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Write Request");
                    totalSize = writeChannelInfoOffset + writeChannelInfoLength - 64;
                }
                fileId = bytesToHexString(Bytes(&rawData.at(16), &rawData.at(32)));
                writeOffset = *(uint64_t*) &rawData.at(8);
            }
            std::string fileId = "";
            uint64_t writeOffset = 0;
            uint32_t writeLength = 0;
            uint16_t dataOffset = 0;
        };


        class WriteResponse : public SmbMessage {
        public:
            WriteResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 17)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Write Response");
                // size of write response is always 16 although the structureSize field is set to 17
                totalSize = 16;
            }
        };


        class OplockBreakMessage : public SmbMessage {
        public:
            OplockBreakMessage(const uint8_t* data, size_t len) : SmbMessage(len) {
                // includes Oplock/Lease Break Notification, Acknowledgement and Response
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 24 && structureSize != 36 && structureSize != 44)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Oplock/Lease Break Message");

                totalSize = structureSize;
            }
        };


        class LockRequest : public SmbMessage {
        public:
            LockRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 48)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Lock Request");

                const uint16_t lockCount = *(uint16_t*) &rawData.at(2);
                if (lockCount == 0)
                    totalSize = 48;
                else {
                    if ((size_t)(48 + (lockCount*24)) > len)
                        throw SmbError("Invalid buffer values in SMB2 Lock Request");
                    totalSize = 48 + (lockCount*24);
                }
            }
        };


        class IoctlRequest : public SmbMessage {
        public:
            IoctlRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 57)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Ioctl Request");

                const uint32_t inputOffset = *(uint32_t*) &rawData.at(24);
                const uint32_t inputCount = *(uint32_t*) &rawData.at(28);

                if (inputOffset == 0 && inputCount == 0)
                    totalSize = 57;
                else {
                    if ((size_t)(inputOffset + inputCount - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Ioctl Request");
                    totalSize = inputOffset + inputCount - 64;
                }

                const uint32_t extractedCtlCode = *(uint32_t*) &rawData.at(4);
                if (ctlCodeStrings.find(extractedCtlCode) != ctlCodeStrings.end())
                    ctlCode = extractedCtlCode;
                else
                    ctlCode = CtlCode::FSCTL_UNKNOWN;

                fileId = bytesToHexString(Bytes(&rawData.at(8), &rawData.at(24)));
            }
            uint32_t ctlCode = CtlCode::FSCTL_UNKNOWN;
            std::string fileId = "";
        };


        class IoctlResponse : public SmbMessage {
        public:
            IoctlResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 49)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Ioctl Response");

                const uint32_t outputOffset = *(uint32_t*) &rawData.at(32);
                const uint32_t outputCount = *(uint32_t*) &rawData.at(36);

                if (outputOffset == 0 && outputCount == 0)
                    totalSize = 49;
                else {
                    if ((size_t)(outputOffset + outputCount - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Ioctl Response");
                    totalSize = outputOffset + outputCount - 64;
                }
            }
        };


        class QueryDirectoryRequest : public SmbMessage {
        public:
            QueryDirectoryRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 33)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Query Directory Request");

                const uint16_t fileNameOffset = *(uint16_t*) &rawData.at(24);
                const uint16_t fileNameLength = *(uint16_t*) &rawData.at(26);

                if (fileNameOffset == 0 && fileNameLength == 0)
                    totalSize = 33;
                else {
                    if ((size_t)(fileNameOffset + fileNameLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Query Directory Request");
                    totalSize = fileNameOffset + fileNameLength - 64;
                }

                const uint8_t extractedInfoClass = rawData.at(2);
                if (fileInfoClassStrings.find(extractedInfoClass) != fileInfoClassStrings.end())
                    fileInfoClass = extractedInfoClass;
                else
                    fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;
                fileId = bytesToHexString(Bytes(&rawData.at(8), &rawData.at(24)));
                searchPattern = wstrToStr(Bytes(&rawData.at(fileNameOffset - 64), &rawData.at(fileNameOffset - 64 + fileNameLength - 1)));
            }
            uint8_t fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;
            std::string fileId = "";
            std::string searchPattern = "";
        };


        class QueryDirectoryResponse : public SmbMessage {
        public:
            QueryDirectoryResponse(const uint8_t* data, size_t len, uint8_t fileInfoClass) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Query Directory Response");

                const uint16_t outputBufferOffset = *(uint16_t*) &rawData.at(2);
                const uint32_t outputBufferLength = *(uint32_t*) &rawData.at(4);

                if (outputBufferOffset == 0 && outputBufferLength == 0)
                    totalSize = 9;
                else {
                    if ((size_t)(outputBufferOffset + outputBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Query Directory Response");
                    totalSize = outputBufferOffset + outputBufferLength - 64;

                    fileInfos = parseFileInformation(Bytes(&rawData.at(outputBufferOffset - 64),
                                        &rawData[outputBufferOffset + outputBufferLength - 64]), fileInfoClass);
                }
            }
            std::vector<std::shared_ptr<FileInformation>> fileInfos;

        private:
            std::vector<std::shared_ptr<FileInformation>> const parseFileInformation(const Bytes &rawContent, uint8_t fileInfoClass) {
                std::vector<std::shared_ptr<FileInformation>> result(0);
                const std::set<uint8_t> allowedFileInfos = { FileInfoClass::FILE_DIRECTORY_INFORMATION, FileInfoClass::FILE_FULL_DIRECTORY_INFORMATION,
                                                            FileInfoClass::FILE_ID_FULL_DIRECTORY_INFORMATION, FileInfoClass::FILE_BOTH_DIRECTORY_INFORMATION,
                                                             FileInfoClass::FILE_ID_BOTH_DIRECTORY_INFORMATION, FileInfoClass::FILE_ID_EXTD_DIRECTORY_INFORMATION };
                if (allowedFileInfos.find(fileInfoClass) == allowedFileInfos.end())
                    return result;

                LOG_TRACE << "parsing file infos from query directory response";
                Bytes tempFileInfoBuffer(rawContent.begin(), rawContent.end());
                uint32_t nextEntryOffset = 0;
                do {
                    std::shared_ptr<FileInformation> currFileInfo = std::make_shared<FileInformation>(tempFileInfoBuffer, fileInfoClass);
                    result.push_back(currFileInfo);

                    nextEntryOffset = *(uint32_t*) &tempFileInfoBuffer.at(0);
                    if (nextEntryOffset + 64 > tempFileInfoBuffer.size())
                        break;
                    tempFileInfoBuffer.erase(tempFileInfoBuffer.begin(), tempFileInfoBuffer.begin() + nextEntryOffset);
                } while (nextEntryOffset != 0);

                return result;
            };
        };


        class ChangeNotifyRequest: public SmbMessage {
        public:
            ChangeNotifyRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 32)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Change Notify Request");

                totalSize = 32;
            }
        };


        class ChangeNotifyResponse : public SmbMessage {
        public:
            ChangeNotifyResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Change Notify Response");

                const uint16_t outputBufferOffset = *(uint16_t*) &rawData.at(2);
                const uint32_t outputBufferLength = *(uint32_t*) &rawData.at(4);

                if (outputBufferLength == 0)
                    totalSize = 9;
                else {
                    if ((size_t)(outputBufferOffset + outputBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Change Notify Response");
                    totalSize = outputBufferOffset + outputBufferLength - 64;
                }
            }
        };


        class QueryInfoRequest : public SmbMessage {
        public:
            QueryInfoRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 41)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Query Info Request");

                const uint16_t inputBufferOffset = *(uint16_t*) &rawData.at(8);
                const uint32_t inputBufferLength = *(uint32_t*) &rawData.at(12);

                if (inputBufferOffset == 0 && inputBufferLength == 0)
                    totalSize = 41;
                else {
                    if ((size_t)(inputBufferOffset + inputBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Query Info Request");
                    totalSize = inputBufferOffset + inputBufferLength - 64;
                }

                const uint8_t extractedInfoType = rawData.at(2);
                if (extractedInfoType < 5)
                    infoType = extractedInfoType;
                else
                    infoType = QueryInfoType::SMB2_0_INFO_UNKNOWN;

                const uint8_t extractedInfoClass = rawData.at(3);
                if (infoType == QueryInfoType::SMB2_0_INFO_FILE) {
                    if (fileInfoClassStrings.find(extractedInfoClass) != fileInfoClassStrings.end())
                        fileInfoClass = extractedInfoClass;
                    else
                        fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;

                } else if (infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM) {
                    if (fsInfoClassStrings.find(extractedInfoClass) != fsInfoClassStrings.end())
                        fileInfoClass = extractedInfoClass;
                    else
                        fileInfoClass = FsInfoClass::FILE_FS_UNKNOWN_INFORMATION;
                }

                fileId = bytesToHexString(Bytes(&rawData.at(24), &rawData[40]));
            }
            uint8_t infoType = QueryInfoType::SMB2_0_INFO_UNKNOWN;
            uint8_t fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;
            std::string fileId = "";
        };


        class QueryInfoResponse : public SmbMessage {
        public:
            QueryInfoResponse(const uint8_t* data, size_t len, const std::shared_ptr<QueryInfoRequestData> &queryInfoRequestData) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 9)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Query Info Response");

                const uint16_t outputBufferOffset = *(uint16_t*) &rawData.at(2);
                const uint32_t outputBufferLength = *(uint32_t*) &rawData.at(4);

                if (outputBufferOffset == 0 || outputBufferLength == 0)
                    totalSize = 9;
                else {
                    if ((size_t)(outputBufferOffset + outputBufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Query Info Response");
                    totalSize = outputBufferOffset + outputBufferLength - 64;
                    if (!queryInfoRequestData)
                        return;

                    if (queryInfoRequestData->infoType == QueryInfoType::SMB2_0_INFO_FILE) {
                        LOG_TRACE << "parsing file infos from query info response";
                        switch (queryInfoRequestData->fileInfoClass) {
                            case FileInfoClass::FILE_ALL_INFORMATION:
                                {
                                    if (outputBufferLength < 100)
                                        throw SmbError("Invalid size of FILE_ALL_INFORMATION in SMB2 Query Info Response");
                                    metaData->creationTime = *(uint64_t*) &rawData.at(outputBufferOffset - 64);
                                    metaData->lastAccessTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 8);
                                    metaData->lastWriteTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 16);
                                    metaData->changeTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 24);
                                    const uint32_t filenameLen = *(uint32_t*) &rawData.at((outputBufferOffset - 64) + 96);
                                    if (100 + filenameLen > outputBufferLength)
                                        throw SmbError("Invalid size of FILE_ALL_INFORMATION in SMB2 Query Info Response");
                                    filename = wstrToStr(Bytes(&rawData.at((outputBufferOffset - 64) + 100),
                                                                &rawData.at((outputBufferOffset - 64) + 100 + filenameLen - 1)));
                                    filename = sanitizeFilename(filename);

                                    const uint32_t extractedFileAttributes = *(uint32_t*) &rawData.at((outputBufferOffset - 64) + 32);
                                    metaData->isDirectory = extractedFileAttributes & 0x10;
                                }
                                break;

                            case FileInfoClass::FILE_BASIC_INFORMATION:
                                {
                                    if (outputBufferLength < 40)
                                        throw SmbError("Invalid size of FILE_BASIC_INFORMATION in SMB2 Query Info Response");
                                    metaData->creationTime = *(uint64_t*) &rawData.at(outputBufferOffset - 64);
                                    metaData->lastAccessTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 8);
                                    metaData->lastWriteTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 16);
                                    metaData->changeTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 24);
                                    const uint32_t extractedFileAttributes = *(uint32_t*) &rawData.at((outputBufferOffset - 64) + 32);
                                    metaData->isDirectory = extractedFileAttributes & 0x10;
                                }
                                break;

                            case FileInfoClass::FILE_NETWORK_OPEN_INFORMATION:
                                {
                                    if (outputBufferLength < 56)
                                        throw SmbError("Invalid size of FILE_NETWORK_OPEN_INFORMATION in SMB2 Query Info Response");
                                    metaData->creationTime = *(uint64_t*) &rawData.at(outputBufferOffset - 64);
                                    metaData->lastAccessTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 8);
                                    metaData->lastWriteTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 16);
                                    metaData->changeTime = *(uint64_t*) &rawData.at((outputBufferOffset - 64) + 24);
                                    const uint32_t extractedFileAttributes = *(uint32_t*) &rawData.at((outputBufferOffset - 64) + 48);
                                    metaData->isDirectory = extractedFileAttributes & 0x10;
                                }
                                break;
                        }
                    }
                }
            }
            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
            std::string filename = "";
        };


        class SetInfoRequest : public SmbMessage {
        public:
            SetInfoRequest(const uint8_t* data, size_t len) : SmbMessage(len) {
                const Bytes rawData(data, data+len);
                const uint16_t structureSize = *(uint16_t*) &rawData.at(0);
                if (structureSize != 33)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Set Info Request");

                const uint32_t bufferLength = *(uint32_t*) &rawData.at(4);
                const uint16_t bufferOffset = *(uint16_t*) &rawData.at(8);

                if (bufferLength == 0)
                    totalSize = 33;
                else {
                    if ((size_t)(bufferOffset + bufferLength - 64) > len)
                        throw SmbError("Invalid buffer values in SMB2 Set Info Request");
                    totalSize = bufferOffset + bufferLength - 64;
                }

                const uint8_t extractedInfoType = rawData.at(2);
                if (extractedInfoType < 5)
                    infoType = extractedInfoType;
                else
                    infoType = QueryInfoType::SMB2_0_INFO_UNKNOWN;

                const uint8_t extractedInfoClass = rawData.at(3);
                if (infoType == QueryInfoType::SMB2_0_INFO_FILE) {
                    if (fileInfoClassStrings.find(extractedInfoClass) != fileInfoClassStrings.end()) {
                        if (extractedInfoClass == FileInfoClass::FILE_BASIC_INFORMATION) {
                            if (bufferLength < 40)
                                throw SmbError("Invalid size of FILE_BASIC_INFORMATION in SMB2 Set Info Request");
                            metaData->creationTime = *(uint64_t*) &rawData.at(bufferOffset - 64);
                            metaData->lastAccessTime = *(uint64_t*) &rawData.at((bufferOffset - 64) + 8);
                            metaData->lastWriteTime = *(uint64_t*) &rawData.at((bufferOffset - 64) + 16);
                            metaData->changeTime = *(uint64_t*) &rawData.at((bufferOffset - 64) + 24);
                            const uint32_t extractedFileAttributes = *(uint32_t*) &rawData.at((bufferOffset - 64) + 32);
                            metaData->isDirectory = extractedFileAttributes & 0x10;
                        }
                        fileInfoClass = extractedInfoClass;
                    } else
                        fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;

                } else if (infoType == QueryInfoType::SMB2_0_INFO_FILESYSTEM) {
                    if (fsInfoClassStrings.find(extractedInfoClass) != fsInfoClassStrings.end())
                        fileInfoClass = extractedInfoClass;
                    else
                        fileInfoClass = FsInfoClass::FILE_FS_UNKNOWN_INFORMATION;
                }

                fileId = bytesToHexString(Bytes(&rawData.at(16), &rawData[32]));
            }
            uint8_t infoType = QueryInfoType::SMB2_0_INFO_UNKNOWN;
            uint8_t fileInfoClass = FileInfoClass::FILE_UNKNOWN_INFORMATION;
            FileMetaDataPtr metaData = std::make_shared<FileMetaData>();
            std::string fileId = "";
        };


        class SetInfoResponse : public SmbMessage {
        public:
            SetInfoResponse(const uint8_t* data, size_t len) : SmbMessage(len) {
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 2)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Set Info Response");

                totalSize = 2;
            }
        };


        class FourByteMessage : public SmbMessage {
        public:
            FourByteMessage(const uint8_t* data, size_t len) : SmbMessage(len) {
                // includes Logoff Request/Response, Tree Disconnect Request/Response, Flush Response,
                // Lock Response, Echo Request/Response and  Cancel Request
                const uint16_t structureSize = *(uint16_t*) data;
                if (structureSize != 4)
                    throw SmbSizeError("Invalid StructureSize in SMB2 Message");

                totalSize = 4;
            }
        };
    }
}

#endif //PCAPFS_SMB_MESSAGES_H
