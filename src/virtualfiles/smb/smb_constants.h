#ifndef PCAPFS_SMB_CONSTANTS_H
#define PCAPFS_SMB_CONSTANTS_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>


namespace pcapfs {
    namespace smb {

        const uint8_t SMB2_MAGIC[4] = {0xFE, 0x53, 0x4D, 0x42};
        const uint8_t SMB1_MAGIC[4] = {0xFF, 0x53, 0x4D, 0x42};

        struct SmbContext {
            uint16_t dialect = 0;
            std::unordered_map<std::string, std::string> fileHandles;
            std::string currentRequestedFile = "";
        };

        typedef std::shared_ptr<SmbContext> SmbContextPtr;

        enum Version : uint16_t {
            SMB_VERSION_2_0_2 = 0x0202,
            SMB_VERSION_2_1 = 0x0210,
            SMB_VERSION_3_0 = 0x0300,
            SMB_VERSION_3_0_2 = 0x0302,
            SMB_VERSION_3_1_1 = 0x0311,
            SMB_VERSION_UNKNOWN = 0x0000
        };

        enum HeaderType : uint8_t {
            SMB2_PACKET_HEADER = 0,
            SMB2_TRANSFORM_HEADER = 1,
            SMB2_COMPRESSION_TRANSFORM_HEADER_UNCHAINED = 2,
            SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED = 3,
            SMB1_PACKET_HEADER = 4,
        };

        enum Smb1HeaderFlags : uint8_t {
            SMB_FLAGS_LOCK_AND_READ_OK = 0x01,
            SMB_FLAGS_BUF_AVAIL = 0x02,
            SMB_FLAGS_CASE_INSENSITIVE = 0x08,
            SMB_FLAGS_CANONICALIZED_PATHS = 0x10,
            SMB_FLAGS_OPLOCK = 0x20,
            SMB_FLAGS_OPBATCH = 0x40,
            SMB_FLAGS_REPLY = 0x80
        };

        enum Smb2HeaderFlags : uint32_t {
            SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001,
            SMB2_FLAGS_ASYNC_COMMAND = 0x00000002,
            SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004,
            SMB2_FLAGS_SIGNED = 0x00000008,
            SMB2_FLAGS_PRIORITY_MASK = 0x00000070,
            SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
        };

        enum CompressionFlags : uint8_t {
            SMB2_COMPRESSION_FLAG_NONE = 0,
            SMB2_COMPRESSION_FLAG_CHAINED = 1
        };

        enum CompressionAlgorithms : uint16_t {
            NONE = 0,
            LZNT1 = 1,
            LZ77 = 2,
            LZ77_HUFFMAN = 3,
            PATTERN_V1 = 4
        };

        enum Smb1Commands : uint8_t {
            SMB_COM_CREATE_DIRECTORY = 0x00,
            SMB_COM_DELETE_DIRECTORY = 0x01,
            SMB_COM_OPEN = 0x02,
            SMB_COM_CREATE = 0x03,
            SMB_COM_CLOSE = 0x04,
            SMB_COM_FLUSH = 0x05,
            SMB_COM_DELETE = 0x06,
            SMB_COM_RENAME = 0x07,
            SMB_COM_QUERY_INFORMATION = 0x08,
            SMB_COM_SET_INFORMATION = 0x09,
            SMB_COM_READ = 0x0A,
            SMB_COM_WRITE = 0x0B,
            SMB_COM_LOCK_BYTE_RANGE = 0x0C,
            SMB_COM_UNLOCK_BYTE_RANGE = 0x0D,
            SMB_COM_CREATE_TEMPORARY = 0x0E,
            SMB_COM_CREATE_NEW = 0x0F,
            SMB_COM_CHECK_DIRECTORY = 0x10,
            SMB_COM_PROCESS_EXIT = 0x11,
            SMB_COM_SEEK = 0x12,
            SMB_COM_LOCK_AND_READ = 0x13,
            SMB_COM_WRITE_AND_UNLOCK = 0x14,
            SMB_COM_READ_RAW = 0x1A,
            SMB_COM_READ_MPX = 0x1B,
            SMB_COM_READ_MPX_SECONDARY = 0x1C,
            SMB_COM_WRITE_RAW = 0x1D,
            SMB_COM_WRITE_MPX = 0x1E,
            SMB_COM_WRITE_MPX_SECONDARY = 0x1F,
            SMB_COM_WRITE_COMPLETE = 0x20,
            SMB_COM_QUERY_SERVER = 0x21,
            SMB_COM_SET_INFORMATION2 = 0x22,
            SMB_COM_QUERY_INFORMATION2 = 0x23,
            SMB_COM_LOCKING_ANDX = 0x24,
            SMB_COM_TRANSACTION = 0x25,
            SMB_COM_TRANSACTION_SECONDARY = 0x26,
            SMB_COM_IOCTL = 0x27,
            SMB_COM_IOCTL_SECONDARY = 0x28,
            SMB_COM_COPY = 0x29,
            SMB_COM_MOVE = 0x2A,
            SMB_COM_ECHO = 0x2B,
            SMB_COM_WRITE_AND_CLOSE = 0x2C,
            SMB_COM_OPEN_ANDX = 0x2D,
            SMB_COM_READ_ANDX = 0x2E,
            SMB_COM_WRITE_ANDX = 0x2F,
            SMB_COM_NEW_FILE_SIZE = 0x30,
            SMB_COM_CLOSE_AND_TREE_DISC = 0x31,
            SMB_COM_TRANSACTION2 = 0x32,
            SMB_COM_TRANSACTION2_SECONDARY = 0x33,
            SMB_COM_FIND_CLOSE2 = 0x34,
            SMB_COM_FIND_NOTIFY_CLOSE = 0x35,
            SMB_COM_TREE_CONNECT = 0x70,
            SMB_COM_TREE_DISCONNECT = 0x71,
            SMB_COM_NEGOTIATE = 0x72,
            SMB_COM_SESSION_SETUP_ANDX = 0x73,
            SMB_COM_LOGOFF_ANDX = 0x74,
            SMB_COM_TREE_CONNECT_ANDX = 0x75,
            SMB_COM_SECURITY_PACKAGE_ANDX = 0x7E,
            SMB_COM_QUERY_INFORMATION_DISK = 0x80,
            SMB_COM_SEARCH = 0x81,
            SMB_COM_FIND = 0x82,
            SMB_COM_FIND_UNIQUE = 0x83,
            SMB_COM_FIND_CLOSE = 0x84,
            SMB_COM_NT_TRANSACT = 0xA0,
            SMB_COM_NT_TRANSACT_SECONDARY = 0xA1,
            SMB_COM_NT_CREATE_ANDX = 0xA2,
            SMB_COM_NT_CANCEL = 0xA4,
            SMB_COM_NT_RENAME = 0xA5,
            SMB_COM_OPEN_PRINT_FILE = 0xC0,
            SMB_COM_WRITE_PRINT_FILE = 0xC1,
            SMB_COM_CLOSE_PRINT_FILE = 0xC2,
            SMB_COM_GET_PRINT_QUEUE = 0xC3,
            SMB_COM_READ_BULK = 0xD8,
            SMB_COM_WRITE_BULK = 0xD9,
            SMB_COM_WRITE_BULK_DATA = 0xDA,
            SMB_COM_INVALID = 0xFE,
            SMB_COM_NO_ANDX_COMMAND = 0xFF
        };

        const std::unordered_map<uint8_t, std::string> smb1CommandStrings = {
            {0x00, "SMB_COM_CREATE_DIRECTORY"},
            {0x01, "SMB_COM_DELETE_DIRECTORY"},
            {0x02, "SMB_COM_OPEN"},
            {0x03, "SMB_COM_CREATE"},
            {0x04, "SMB_COM_CLOSE"},
            {0x05, "SMB_COM_FLUSH"},
            {0x06, "SMB_COM_DELETE"},
            {0x07, "SMB_COM_RENAME"},
            {0x08, "SMB_COM_QUERY_INFORMATION"},
            {0x09, "SMB_COM_SET_INFORMATION"},
            {0x0A, "SMB_COM_READ"},
            {0x0B, "SMB_COM_WRITE"},
            {0x0C, "SMB_COM_LOCK_BYTE_RANGE"},
            {0x0D, "SMB_COM_UNLOCK_BYTE_RANGE"},
            {0x0E, "SMB_COM_CREATE_TEMPORARY"},
            {0x0F, "SMB_COM_CREATE_NEW"},
            {0x10, "SMB_COM_CHECK_DIRECTORY"},
            {0x11, "SMB_COM_PROCESS_EXIT"},
            {0x12, "SMB_COM_SEEK"},
            {0x13, "SMB_COM_LOCK_AND_READ"},
            {0x14, "SMB_COM_WRITE_AND_UNLOCK"},
            {0x1A, "SMB_COM_READ_RAW"},
            {0x1B, "SMB_COM_READ_MPX"},
            {0x1C, "SMB_COM_READ_MPX_SECONDARY"},
            {0x1D, "SMB_COM_WRITE_RAW"},
            {0x1E, "SMB_COM_WRITE_MPX"},
            {0x1F, "SMB_COM_WRITE_MPX_SECONDARY"},
            {0x20, "SMB_COM_WRITE_COMPLETE"},
            {0x21, "SMB_COM_QUERY_SERVER"},
            {0x22, "SMB_COM_SET_INFORMATION2"},
            {0x23, "SMB_COM_QUERY_INFORMATION2"},
            {0x24, "SMB_COM_LOCKING_ANDX"},
            {0x25, "SMB_COM_TRANSACTION"},
            {0x26, "SMB_COM_TRANSACTION_SECONDARY"},
            {0x27, "SMB_COM_IOCTL"},
            {0x28, "SMB_COM_IOCTL_SECONDARY"},
            {0x29, "SMB_COM_COPY"},
            {0x2A, "SMB_COM_MOVE"},
            {0x2B, "SMB_COM_ECHO"},
            {0x2C, "SMB_COM_WRITE_AND_CLOSE"},
            {0x2D, "SMB_COM_OPEN_ANDX"},
            {0x2E, "SMB_COM_READ_ANDX"},
            {0x2F, "SMB_COM_WRITE_ANDX"},
            {0x30, "SMB_COM_NEW_FILE_SIZE"},
            {0x31, "SMB_COM_CLOSE_AND_TREE_DISC"},
            {0x32, "SMB_COM_TRANSACTION2"},
            {0x33, "SMB_COM_TRANSACTION2_SECONDARY"},
            {0x34, "SMB_COM_FIND_CLOSE2"},
            {0x35, "SMB_COM_FIND_NOTIFY_CLOSE"},
            {0x70, "SMB_COM_TREE_CONNECT"},
            {0x71, "SMB_COM_TREE_DISCONNECT"},
            {0x72, "SMB_COM_NEGOTIATE"},
            {0x73, "SMB_COM_SESSION_SETUP_ANDX"},
            {0x74, "SMB_COM_LOGOFF_ANDX"},
            {0x75, "SMB_COM_TREE_CONNECT_ANDX"},
            {0x7E, "SMB_COM_SECURITY_PACKAGE_ANDX"},
            {0x80, "SMB_COM_QUERY_INFORMATION_DISK"},
            {0x81, "SMB_COM_SEARCH"},
            {0x82, "SMB_COM_FIND"},
            {0x83, "SMB_COM_FIND_UNIQUE"},
            {0x84, "SMB_COM_FIND_CLOSE"},
            {0xA0, "SMB_COM_NT_TRANSACT"},
            {0xA1, "SMB_COM_NT_TRANSACT_SECONDARY"},
            {0xA2, "SMB_COM_NT_CREATE_ANDX"},
            {0xA4, "SMB_COM_NT_CANCEL"},
            {0xA5, "SMB_COM_NT_RENAME"},
            {0xC0, "SMB_COM_OPEN_PRINT_FILE"},
            {0xC1, "SMB_COM_WRITE_PRINT_FILE"},
            {0xC2, "SMB_COM_CLOSE_PRINT_FILE"},
            {0xC3, "SMB_COM_GET_PRINT_QUEUE"},
            {0xD8, "SMB_COM_READ_BULK"},
            {0xD9, "SMB_COM_WRITE_BULK"},
            {0xDA, "SMB_COM_WRITE_BULK_DATA"},
            {0xFE, "SMB_COM_INVALID"},
            {0xFF, "SMB_COM_NO_ANDX_COMMAND"}
        };

        enum Smb2Commands : uint16_t {
            SMB2_NEGOTIATE = 0x0000,
            SMB2_SESSION_SETUP = 0x0001,
            SMB2_LOGOFF = 0x0002,
            SMB2_TREE_CONNECT = 0x0003,
            SMB2_TREE_DISCONNECT = 0x0004,
            SMB2_CREATE = 0x0005,
            SMB2_CLOSE = 0x0006,
            SMB2_FLUSH = 0x0007,
            SMB2_READ = 0x0008,
            SMB2_WRITE = 0x0009,
            SMB2_LOCK = 0x000A,
            SMB2_IOCTL = 0x000B,
            SMB2_CANCEL = 0x000C,
            SMB2_ECHO = 0x000D,
            SMB2_QUERY_DIRECTORY = 0x000E,
            SMB2_CHANGE_NOTIFY = 0x000F,
            SMB2_QUERY_INFO = 0x0010,
            SMB2_SET_INFO = 0x0011,
            SMB2_OPLOCK_BREAK = 0x0012
        };

        const std::vector<std::string> smb2CommandStrings = {
            "SMB2_NEGOTIATE",
            "SMB2_SESSION_SETUP",
            "SMB2_LOGOFF",
            "SMB2_TREE_CONNECT",
            "SMB2_TREE_DISCONNECT",
            "SMB2_CREATE",
            "SMB2_CLOSE",
            "SMB2_FLUSH",
            "SMB2_READ",
            "SMB2_WRITE",
            "SMB2_LOCK",
            "SMB2_IOCTL",
            "SMB2_CANCEL",
            "SMB2_ECHO",
            "SMB2_QUERY_DIRECTORY",
            "SMB2_CHANGE_NOTIFY",
            "SMB2_QUERY_INFO",
            "SMB2_SET_INFO",
            "SMB2_OPLOCK_BREAK"
        };

        enum StatusCodes : uint32_t {
            STATUS_PENDING = 0x00000103,
            STATUS_CANCELLED = 0xC000120,
            STATUS_SUCCESS = 0x00000000,
            STATUS_NOT_IMPLEMENTED = 0xC0000002,
            STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
            STATUS_ILLEGAL_FUNCTION = 0xC00000AF,
            STATUS_NO_SUCH_FILE = 0xC000000F,
            STATUS_NO_SUCH_DEVICE = 0xC000000E,
            STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
            STATUS_OBJECT_PATH_INVALID = 0xC0000039,
            STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A,
            STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
            STATUS_DFS_EXIT_PATH_FOUND = 0xC000009B,
            STATUS_REDIRECTOR_NOT_STARTED = 0xC00000FB,
            STATUS_TOO_MANY_OPENED_FILES = 0xC000011F,
            STATUS_ACCESS_DENIED1 = 0xC0000022,
            STATUS_INVALID_LOCK_SEQUENCE = 0xC000001E,
            STATUS_INVALID_VIEW_SIZE = 0xC000001F,
            STATUS_ALREADY_COMMITTED = 0xC0000021,
            STATUS_PORT_CONNECTION_REFUSED = 0xC0000041,
            STATUS_THREAD_IS_TERMINATING = 0xC000004B,
            STATUS_DELETE_PENDING = 0xC0000056,
            STATUS_PRIVILEGE_NOT_HELD = 0xC0000061,
            STATUS_LOGON_FAILURE = 0xC000006D,
            STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
            STATUS_FILE_RENAMED = 0xC00000D5,
            STATUS_PROCESS_IS_TERMINATING = 0xC000010A,
            STATUS_CANNOT_DELETE = 0xC0000121,
            STATUS_FILE_DELETED = 0xC0000123,
            STATUS_SMB_BAD_FID = 0x00060001,
            STATUS_INVALID_HANDLE = 0xC0000008,
            STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024,
            STATUS_PORT_DISCONNECTED = 0xC0000037,
            STATUS_INVALID_PORT_HANDLE = 0xC0000042,
            STATUS_FILE_CLOSED = 0xC0000128,
            STATUS_HANDLE_NOT_CLOSABLE = 0xC0000235,
            STATUS_SECTION_TOO_BIG = 0xC0000040,
            STATUS_TOO_MANY_PAGING_FILES = 0xC0000097,
            STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205,
            STATUS_OS2_INVALID_ACCESS = 0x000C0001,
            STATUS_ACCESS_DENIED2 = 0xC00000CA,
            STATUS_DATA_ERROR1 = 0xC000009C,
            STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101,
            STATUS_NOT_SAME_DEVICE = 0xC00000D4,
            STATUS_NO_MORE_FILES = 0x80000006,
            STATUS_UNSUCCESSFUL = 0xC0000001,
            STATUS_FILE_LOCK_CONFLICT = 0xC0000054,
            STATUS_LOCK_NOT_GRANTED = 0xC0000055,
            STATUS_END_OF_FILE = 0xC0000011,
            STATUS_NOT_SUPPORTED = 0XC00000BB,
            STATUS_OBJECT_NAME_COLLISION = 0xC0000035,
            STATUS_INVALID_PARAMETER = 0xC000000D,
            STATUS_OS2_INVALID_LEVEL = 0x007C0001,
            STATUS_OS2_NEGATIVE_SEEK = 0x00830001,
            STATUS_RANGE_NOT_LOCKED = 0xC000007E,
            STATUS_OS2_NO_MORE_SIDS = 0x00710001,
            STATUS_OS2_CANCEL_VIOLATION = 0x00AD0001,
            STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED = 0x00AE0001,
            STATUS_INVALID_INFO_CLASS = 0xC0000003,
            STATUS_INVALID_PIPE_STATE = 0xC00000AD,
            STATUS_INVALID_READ_MODE = 0xC00000B4,
            STATUS_OS2_CANNOT_COPY = 0x010A0001,
            STATUS_INSTANCE_NOT_AVAILABLE = 0xC00000AB,
            STATUS_PIPE_NOT_AVAILABLE = 0xC00000AC,
            STATUS_PIPE_BUSY = 0xC00000AE,
            STATUS_PIPE_CLOSING = 0xC00000B1,
            STATUS_PIPE_EMPTY = 0xC00000D9,
            STATUS_PIPE_DISCONNECTED = 0xC00000B0,
            STATUS_BUFFER_OVERFLOW = 0x80000005,
            STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
            STATUS_EA_TOO_LARGE = 0xC0000050,
            STATUS_OS2_EAS_DIDNT_FIT = 0x01130001,
            STATUS_EAS_NOT_SUPPORTED = 0xC000004F,
            STATUS_OS2_EA_ACCESS_DENIED = 0x03E20001,
            STATUS_NOTIFY_ENUM_DIR = 0x0000010C,
            STATUS_INVALID_SMB = 0x00010002,
            STATUS_WRONG_PASSWORD = 0xC000006A,
            STATUS_PATH_NOT_COVERED = 0xC0000257,
            STATUS_NETWORK_ACCESS_DENIED = 0xC00000CA,
            STATUS_NETWORK_NAME_DELETED = 0xC00000C9,
            STATUS_SMB_BAD_TID = 0x00050002,
            STATUS_BAD_NETWORK_NAME = 0xC00000CC,
            STATUS_BAD_DEVICE_TYPE = 0xC00000CB,
            STATUS_SMB_BAD_COMMAND = 0x00160002,
            STATUS_PRINT_QUEUE_FULL  = 0xC00000C6,
            STATUS_NO_SPOOL_SPACE = 0xC00000C7,
            STATUS_PRINT_CANCELLED = 0xC00000C8,
            STATUS_UNEXPECTED_NETWORK_ERROR = 0xC00000C4,
            STATUS_IO_TIMEOUT = 0xC00000B5,
            STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0,
            STATUS_TOO_MANY_SESSIONS = 0xC00000CE,
            STATUS_SMB_BAD_UID = 0x005B0002,
            STATUS_SMB_USE_MPX = 0x00FA0002,
            STATUS_SMB_USE_STANDARD = 0x00FB0002,
            STATUS_SMB_CONTINUE_MPX = 0x00FC0002,
            STATUS_ACCOUNT_DISABLED = 0xC0000072,
            STATUS_ACCOUNT_EXPIRED = 0xC0000193,
            STATUS_INVALID_WORKSTATION = 0xC0000070,
            STATUS_INVALID_LOGON_HOURS = 0xC000006F,
            STATUS_PASSWORD_EXPIRED = 0xC0000071,
            STATUS_PASSWORD_MUST_CHANGE = 0xC0000224,
            STATUS_SMB_NO_SUPPORT = 0XFFFF0002,
            STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2,
            STATUS_NO_MEDIA_IN_DEVICE = 0xC0000013,
            STATUS_INVALID_DEVICE_STATE = 0xC0000184,
            STATUS_DATA_ERROR2 = 0xC000003E,
            STATUS_CRC_ERROR = 0xC000003F,
            STATUS_DISK_CORRUPT_ERROR = 0xC0000032,
            STATUS_NONEXISTENT_SECTOR = 0xC0000015,
            STATUS_DEVICE_PAPER_EMPTY = 0x8000000E,
            STATUS_SHARING_VIOLATION = 0xC0000043,
            STATUS_WRONG_VOLUME = 0xC0000012,
            STATUS_DISK_FULL = 0xC000007F,
            STATUS_FS_DRIVER_REQUIRED = 0xC000019C
        };

        const std::unordered_map<uint32_t, std::string> statusCodeStrings = {
            {0x00000103, "STATUS_PENDING"},
            {0xC0000120, "STATUS_CANCELLED"},
            {0x00000000, "STATUS_SUCCESS"},
            {0xC0000002, "STATUS_NOT_IMPLEMENTED"},
            {0xC0000010, "STATUS_INVALID_DEVICE_REQUEST"},
            {0xC00000AF, "STATUS_ILLEGAL_FUNCTION"},
            {0xC000000F, "STATUS_NO_SUCH_FILE"},
            {0xC000000E, "STATUS_NO_SUCH_DEVICE"},
            {0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND"},
            {0xC0000039, "STATUS_OBJECT_PATH_INVALID"},
            {0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND"},
            {0xC000003B, "STATUS_OBJECT_PATH_SYNTAX_BAD"},
            {0xC000009B, "STATUS_DFS_EXIT_PATH_FOUND"},
            {0xC00000FB, "STATUS_REDIRECTOR_NOT_STARTED"},
            {0xC000011F, "STATUS_TOO_MANY_OPENED_FILES"},
            {0xC0000022, "STATUS_ACCESS_DENIED"},
            {0xC000001E, "STATUS_INVALID_LOCK_SEQUENCE"},
            {0xC000001F, "STATUS_INVALID_VIEW_SIZE"},
            {0xC0000021, "STATUS_ALREADY_COMMITTED"},
            {0xC0000041, "STATUS_PORT_CONNECTION_REFUSED"},
            {0xC000004B, "STATUS_THREAD_IS_TERMINATING"},
            {0xC0000056, "STATUS_DELETE_PENDING"},
            {0xC0000061, "STATUS_PRIVILEGE_NOT_HELD"},
            {0xC000006D, "STATUS_LOGON_FAILURE"},
            {0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY"},
            {0xC00000D5, "STATUS_FILE_RENAMED"},
            {0xC000010A, "STATUS_PROCESS_IS_TERMINATING"},
            {0xC0000121, "STATUS_CANNOT_DELETE"},
            {0xC0000123, "STATUS_FILE_DELETED"},
            {0x00060001, "STATUS_SMB_BAD_FID"},
            {0xC0000008, "STATUS_INVALID_HANDLE"},
            {0xC0000024, "STATUS_OBJECT_TYPE_MISMATCH"},
            {0xC0000037, "STATUS_PORT_DISCONNECTED"},
            {0xC0000042, "STATUS_INVALID_PORT_HANDLE"},
            {0xC0000128, "STATUS_FILE_CLOSED"},
            {0xC0000235, "STATUS_HANDLE_NOT_CLOSABLE"},
            {0xC0000040, "STATUS_SECTION_TOO_BIG"},
            {0xC0000097, "STATUS_TOO_MANY_PAGING_FILES"},
            {0xC0000205, "STATUS_INSUFF_SERVER_RESOURCES"},
            {0x000C0001, "STATUS_OS2_INVALID_ACCESS"},
            {0xC00000CA, "STATUS_ACCESS_DENIED"},
            {0xC000009C, "STATUS_DATA_ERROR1"},
            {0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY"},
            {0xC00000D4, "STATUS_NOT_SAME_DEVICE"},
            {0x80000006, "STATUS_NO_MORE_FILES"},
            {0xC0000001, "STATUS_UNSUCCESSFUL"},
            {0xC0000054, "STATUS_FILE_LOCK_CONFLICT"},
            {0xC0000055, "STATUS_LOCK_NOT_GRANTED"},
            {0xC0000011, "STATUS_END_OF_FILE"},
            {0XC00000BB, "STATUS_NOT_SUPPORTED"},
            {0xC0000035, "STATUS_OBJECT_NAME_COLLISION"},
            {0xC000000D, "STATUS_INVALID_PARAMETER"},
            {0x007C0001, "STATUS_OS2_INVALID_LEVEL"},
            {0x00830001, "STATUS_OS2_NEGATIVE_SEEK"},
            {0xC000007E, "STATUS_RANGE_NOT_LOCKED"},
            {0x00710001, "STATUS_OS2_NO_MORE_SIDS"},
            {0x00AD0001, "STATUS_OS2_CANCEL_VIOLATION"},
            {0x00AE0001, "STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED"},
            {0xC0000003, "STATUS_INVALID_INFO_CLASS"},
            {0xC00000AD, "STATUS_INVALID_PIPE_STATE"},
            {0xC00000B4, "STATUS_INVALID_READ_MODE"},
            {0x010A0001, "STATUS_OS2_CANNOT_COPY"},
            {0xC00000AB, "STATUS_INSTANCE_NOT_AVAILABLE"},
            {0xC00000AC, "STATUS_PIPE_NOT_AVAILABLE"},
            {0xC00000AE, "STATUS_PIPE_BUSY"},
            {0xC00000B1, "STATUS_PIPE_CLOSING"},
            {0xC00000D9, "STATUS_PIPE_EMPTY"},
            {0xC00000B0, "STATUS_PIPE_DISCONNECTED"},
            {0x80000005, "STATUS_BUFFER_OVERFLOW"},
            {0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED"},
            {0xC0000050, "STATUS_EA_TOO_LARGE"},
            {0x01130001, "STATUS_OS2_EAS_DIDNT_FIT"},
            {0xC000004F, "STATUS_EAS_NOT_SUPPORTED"},
            {0x03E20001, "STATUS_OS2_EA_ACCESS_DENIED"},
            {0x0000010C, "STATUS_NOTIFY_ENUM_DIR"},
            {0x00010002, "STATUS_INVALID_SMB"},
            {0xC000006A, "STATUS_WRONG_PASSWORD"},
            {0xC0000257, "STATUS_PATH_NOT_COVERED"},
            {0xC00000CA, "STATUS_NETWORK_ACCESS_DENIED"},
            {0xC00000C9, "STATUS_NETWORK_NAME_DELETED"},
            {0x00050002, "STATUS_SMB_BAD_TID"},
            {0xC00000CC, "STATUS_BAD_NETWORK_NAME"},
            {0xC00000CB, "STATUS_BAD_DEVICE_TYPE"},
            {0x00160002, "STATUS_SMB_BAD_COMMAND"},
            {0xC00000C6, "STATUS_PRINT_QUEUE_FULL"},
            {0xC00000C7, "STATUS_NO_SPOOL_SPACE"},
            {0xC00000C8, "STATUS_PRINT_CANCELLED"},
            {0xC00000C4, "STATUS_UNEXPECTED_NETWORK_ERROR"},
            {0xC00000B5, "STATUS_IO_TIMEOUT"},
            {0xC00000D0, "STATUS_REQUEST_NOT_ACCEPTED"},
            {0xC00000CE, "STATUS_TOO_MANY_SESSIONS"},
            {0x005B0002, "STATUS_SMB_BAD_UID"},
            {0x00FA0002, "STATUS_SMB_USE_MPX"},
            {0x00FB0002, "STATUS_SMB_USE_STANDARD"},
            {0x00FC0002, "STATUS_SMB_CONTINUE_MPX"},
            {0xC0000072, "STATUS_ACCOUNT_DISABLED"},
            {0xC0000193, "STATUS_ACCOUNT_EXPIRED"},
            {0xC0000070, "STATUS_INVALID_WORKSTATION"},
            {0xC000006F, "STATUS_INVALID_LOGON_HOURS"},
            {0xC0000071, "STATUS_PASSWORD_EXPIRED"},
            {0xC0000224, "STATUS_PASSWORD_MUST_CHANGE"},
            {0XFFFF0002, "STATUS_SMB_NO_SUPPORT"},
            {0xC00000A2, "STATUS_MEDIA_WRITE_PROTECTED"},
            {0xC0000013, "STATUS_NO_MEDIA_IN_DEVICE"},
            {0xC0000184, "STATUS_INVALID_DEVICE_STATE"},
            {0xC000003E, "STATUS_DATA_ERROR"},
            {0xC000003F, "STATUS_CRC_ERROR"},
            {0xC0000032, "STATUS_DISK_CORRUPT_ERROR"},
            {0xC0000015, "STATUS_NONEXISTENT_SECTOR"},
            {0x8000000E, "STATUS_DEVICE_PAPER_EMPTY"},
            {0xC0000043, "STATUS_SHARING_VIOLATION"},
            {0xC0000012, "STATUS_WRONG_VOLUME"},
            {0xC000007F, "STATUS_DISK_FULL"},
            {0xC000019C, "STATUS_FS_DRIVER_REQUIRED"}
        };

        enum CreateDisposition : uint32_t {
            FILE_SUPERSEDE = 0x00000000,
            FILE_OPEN = 0x00000001,
            FILE_CREATE = 0x00000002,
            FILE_OPEN_IF = 0x00000003,
            FILE_OVERWRITE = 0x00000004,
            FILE_OVERWRITE_IF = 0x00000005,
            DISPOSITION_UNKNOWN = 0x00000006
        };

        const std::vector<std::string> createDispositionStrings = {
            "FILE_SUPERSEDE",
            "FILE_OPEN",
            "FILE_CREATE",
            "FILE_OPEN_IF",
            "FILE_OVERWRITE",
            "FILE_OVERWRITE_IF",
            "DISPOSITION_UNKNOWN"
        };

        enum CreateAction : uint32_t {
            FILE_SUPERSEDED = 0x00000000,
            FILE_OPENED = 0x00000001,
            FILE_CREATED = 0x00000002,
            FILE_OVERWRITTEN = 0x00000003,
            ACTION_UNKNOWN = 0x00000004
        };

        const std::vector<std::string> createActionStrings = {
            "FILE_SUPERSEDED",
            "FILE_OPENED",
            "FILE_CREATED",
            "FILE_OVERWRITTEN",
            "ACTION_UNKNOWN"
        };

        enum QueryInfoType : uint8_t {
            SMB2_0_INFO_FILE = 0x01,
            SMB2_0_INFO_FILESYSTEM = 0x02,
            SMB2_0_INFO_SECURITY = 0x03,
            SMB2_0_INFO_QUOTA = 0x04,
            SMB2_0_INFO_UNKNOWN = 0xFF
        };

        const std::unordered_map<uint8_t, std::string> queryInfoTypeStrings = {
            {0x01, "SMB2_0_INFO_FILE"},
            {0x02, "SMB2_0_INFO_FILESYSTEM"},
            {0x03, "SMB2_0_INFO_SECURITY"},
            {0x04, "SMB2_0_INFO_QUOTA"},
            {0xFF, "SMB2_0_INFO_UNKNOWN"}
        };

        enum FileInfoClass : uint8_t {
            FILE_ACCESS_INFORMATION = 8,
            FILE_ALIGNMENT_INFORMATION = 17,
            FILE_ALL_INFORMATION = 18,
            FILE_ALLOCATION_INFORMATION = 19,
            FILE_ALTERNATE_NAME_INFORMATION = 21,
            FILE_ATTRIBUTE_TAG_INFORMATION = 35,
            FILE_BASIC_INFORMATION = 4,
            FILE_BOTH_DIRECTORY_INFORMATION = 3,
            FILE_COMPRESSION_INFORMATION = 28,
            FILE_DIRECTORY_INFORMATION = 1,
            FILE_DISPOSITION_INFORMATION = 13,
            FILE_EA_INFORMATION = 7,
            FILE_END_OF_FILE_INFORMATION = 20,
            FILE_FULL_DIRECTORY_INFORMATION = 2,
            FILE_FULL_EA_INFORMATION = 15,
            FILE_HARD_LINK_INFORMATION = 46,
            FILE_ID_BOTH_DIRECTORY_INFORMATION = 37,
            FILE_ID_EXTD_DIRECTORY_INFORMATION = 60,
            FILE_ID_FULL_DIRECTORY_INFORMATION = 38,
            FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION = 50,
            FILE_ID_INFORMATION = 59,
            FILE_INTERNAL_INFORMATION = 6,
            FILE_LINK_INFORMATION = 11,
            FILE_MAIL_SLOT_QUERY_INFORMATION = 26,
            FILE_MAIL_SLOT_SET_INFORMATION = 27,
            FILE_MODE_INFORMATION = 16,
            FILE_MOVE_CLUSTER_INFORMATION = 31,
            FILE_NAME_INFORMATION = 9,
            FILE_NAMES_INFORMATION = 12,
            FILE_NETWORK_OPEN_INFORMATION = 34,
            FILE_NORMALIZED_NAME_INFORMATION = 48,
            FILE_OBJECTID_INFORMATION = 29,
            FILE_PIPE_INFORMATION = 23,
            FILE_PIPE_LOCAL_INFORMATION = 24,
            FILE_PIPE_REMOTE_INFORMATION = 25,
            FILE_POSITION_INFORMATION = 14,
            FILE_QUOTA_INFORMATION = 32,
            FILE_RENAME_INFORMATION = 10,
            FILE_REPARSE_POINT_INFORMATION = 33,
            FILE_SFIO_RESERVE_INFORMATION = 44,
            FILE_SFIO_VOLUME_INFORMATION = 45,
            FILE_SHORT_NAME_INFORMATION = 40,
            FILE_STANDARD_INFORMATION = 5,
            FILE_STANDARD_LINK_INFORMATION = 54,
            FILE_STREAM_INFORMATION = 22,
            FILE_TRACKING_INFORMATION = 36,
            FILE_VALID_DATA_LENGTH_INFORMATION = 39,
            FILE_UNKNOWN_INFORMATION = 255
        };

        const std::unordered_map<uint8_t, std::string> fileInfoClassStrings = {
            {8, "FileAccessInformation"},
            {17, "FileAlignmentInformation"},
            {18, "FileAllInformation"},
            {19, "FileAllocationInformation"},
            {21, "FileAlternateNameInformation"},
            {35, "FileAttributeTagInformation"},
            {4, "FileBasicInformation"},
            {3, "FileBothDirectoryInformation"},
            {28, "FileCompressionInformation"},
            {1, "FileDirectoryInformation"},
            {13, "FileDispositionInformation"},
            {7, "FileEaInformation"},
            {20, "FileEndOfFileInformation"},
            {2, "FileFullDirectoryInformation"},
            {15, "FileFullEaInformation"},
            {46, "FileHardLinkInformation"},
            {37, "FileIdBothDirectoryInformation"},
            {60, "FileIdExtdDirectoryInformation"},
            {38, "FileIdFullDirectoryInformation"},
            {50, "FileIdGlobalTxDirectoryInformation"},
            {59, "FileIdInformation"},
            {6, "FileInternalInformation"},
            {11, "FileLinkInformation"},
            {26, "FileMailslotQueryInformation"},
            {27, "FileMailslotSetInformation"},
            {16, "FileModeInformation"},
            {31, "FileMoveClusterInformation"},
            {9, "FileNameInformation"},
            {12, "FileNamesInformation"},
            {34, "FileNetworkOpenInformation"},
            {48, "FileNormalizedNameInformation"},
            {29, "FileObjectIdInformation"},
            {23, "FilePipeInformation"},
            {24, "FilePipeLocalInformation"},
            {25, "FilePipeRemoteInformation"},
            {14, "FilePositionInformation"},
            {32, "FileQuotaInformation"},
            {10, "FileRenameInformation"},
            {33, "FileReparsePointInformation"},
            {44, "FileSfioReserveInformation"},
            {45, "FileSfioVolumeInformation"},
            {40, "FileShortNameInformation"},
            {5, "FileStandardInformation"},
            {54, "FileStandardLinkInformation"},
            {22, "FileStreamInformation"},
            {36, "FileTrackingInformation"},
            {39, "FileValidDataLengthInformation"},
            {255, "FILE_UNKNOWN_INFORMATION"}
        };

        enum FsInfoClass : uint8_t {
            FILE_FS_VOLUME_INFORMATION = 1,
            FILE_FS_LABEL_INFORMATION = 2,
            FILE_FS_SIZE_INFORMATION = 3,
            FILE_FS_DEVICE_INFORMATION = 4,
            FILE_FS_ATTRIBUTE_INFORMATION = 5,
            FILE_FS_CONTROL_INFORMATION = 6,
            FILE_FS_FULL_SIZE_INFORMATION = 7,
            FILE_FS_OBJECT_ID_INFORMATION = 8,
            FILE_FS_DRIVER_PATH_INFORMATION = 9,
            FILE_FS_VOLUME_FLAGS_INFORMATION = 10,
            FILE_FS_SECTOR_SIZE_INFORMATION = 11,
            FILE_FS_UNKNOWN_INFORMATION = 255
        };

        const std::unordered_map<uint8_t, std::string> fsInfoClassStrings = {
            {1, "FileFsVolumeInformation"},
            {2, "FileFsLabelInformation"},
            {3, "FileFsSizeInformation"},
            {4, "FileFsDeviceInformation"},
            {5, "FileFsAttributeInformation"},
            {6, "FileFsControlInformation"},
            {7, "FileFsFullSizeInformation"},
            {8, "FileFsObjectIdInformation"},
            {9, "FileFsDriverPathInformation"},
            {10, "FileFsVolumeFlagsInformation"},
            {11, "FileFsSectorSizeInformation"},
            {255, "FILE_FS_UNKNOWN_INFORMATION"},
        };

        enum CtlCode : uint32_t {
            FSCTL_DFS_GET_REFERRALS = 0x00060194,
            FSCTL_PIPE_PEEK = 0x0011400C,
            FSCTL_PIPE_WAIT = 0x00110018,
            FSCTL_PIPE_TRANSCEIVE = 0x0011C017,
            FSCTL_SRV_COPYCHUNK = 0x001440F2,
            FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064,
            FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078,
            FSCTL_SRV_READ_HASH = 0x001441bb,
            FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2,
            FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4,
            FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC,
            FSCTL_SET_REPARSE_POINT = 0x000900A4,
            FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0,
            FSCTL_FILE_LEVEL_TRIM = 0x00098208,
            FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204,
            FSCTL_UNKNOWN = 0xFFFFFFFF,
        };

        const std::unordered_map<uint32_t, std::string> ctlCodeStrings = {
            {0x00060194, "FSCTL_DFS_GET_REFERRALS"},
            {0x0011400C, "FSCTL_PIPE_PEEK"},
            {0x00110018, "FSCTL_PIPE_WAIT"},
            {0x0011C017, "FSCTL_PIPE_TRANSCEIVE"},
            {0x001440F2, "FSCTL_SRV_COPYCHUNK"},
            {0x00144064, "FSCTL_SRV_ENUMERATE_SNAPSHOTS"},
            {0x00140078, "FSCTL_SRV_REQUEST_RESUME_KEY"},
            {0x001441bb, "FSCTL_SRV_READ_HASH"},
            {0x001480F2, "FSCTL_SRV_COPYCHUNK_WRITE"},
            {0x001401D4, "FSCTL_LMR_REQUEST_RESILIENCY"},
            {0x001401FC, "FSCTL_QUERY_NETWORK_INTERFACE_INFO"},
            {0x000900A4, "FSCTL_SET_REPARSE_POINT"},
            {0x000601B0, "FSCTL_DFS_GET_REFERRALS_EX"},
            {0x00098208, "FSCTL_FILE_LEVEL_TRIM"},
            {0x00140204, "FSCTL_VALIDATE_NEGOTIATE_INFO"},
            {0xFFFFFFFF, "FSCTL_UNKNOWN"}
        };
    }
}

#endif //PCAPFS_SMB_CONSTANTS_H