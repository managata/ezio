//
//
//

package main

const (
	ID_MAGIC        uint32 = 0x257a
	ID_NULL                = 0x00
	ID_DATA                = 0x01
	ID_META_DATA           = 0x02
	ID_META_LIST           = 0x03
	ID_BLOCK_SIZE          = 0x04
	ID_BLOCK_DATA          = 0x05
	ID_BLOCK_PARITY        = 0x06
	ID_CHECK_SUM           = 0x07
	ID_PARITY              = 0x08
	ID_VOID                = 0x6c
	ID_PAD                 = 0x7c
	ID_EOF                 = 0x7e

	ID_SUITE      = 0x10
	ID_KEK_SALT   = 0x11
	ID_NONCE      = 0x12
	ID_NONCE_MASK = 0x13
	ID_CEK        = 0x14

	ID_POSITION  = 0x20
	ID_PATH      = 0x21
	ID_MODE      = 0x22
	ID_SIZE      = 0x23
	ID_SIZE_ENC  = 0x24
	ID_HASH      = 0x25
	ID_HASH_META = 0x26
	ID_MTIME     = 0x27
	ID_MTIME_NS  = 0x28
	ID_SIGNATURE = 0x29

	ID_DEVICE   = 0x31
	ID_INODE    = 0x32
	ID_NLINK    = 0x33
	ID_UID      = 0x34
	ID_GID      = 0x35
	ID_MAJOR    = 0x36
	ID_MINOR    = 0x37
	ID_ATIME    = 0x38
	ID_ATIME_NS = 0x39
	ID_CTIME    = 0x3a
	ID_CTIME_NS = 0x3b
	ID_SYMLINK  = 0x3c
	ID_EX_ATTR  = 0x3d

	ID_BTIME    = 0x40
	ID_BTIME_NS = 0x41

	ID_VERSION_INFO      = 0x0101
	ID_ARCHIVE_INFO      = 0x0102
	ID_ENCRYPT_INFO      = 0x0103
	ID_COMPRESS_INFO     = 0x0104
	ID_HASH_INFO         = 0x0105
	ID_MAC_INFO          = 0x0106
	ID_SIGN_INFO         = 0x0107
	ID_ERASURE_CODE_INFO = 0x0108
	ID_AUTHOR_INFO       = 0x0109
	ID_TIME_INFO         = 0x010a
	ID_TIMEN_INFO        = 0x010b
	ID_OS_INFO           = 0x010c
	ID_FS_INFO           = 0x010d

	ID_EXTRA_DATA  = 0x0200
	ID_SIZE_2      = 0x0201
	ID_HASH_2      = 0x0202
	ID_DATA_SIZE_2 = 0x0203
	ID_DATA_HASH_2 = 0x0204
	ID_SIZE_3      = 0x0205
	ID_HASH_3      = 0x0206
	ID_DATA_SIZE_3 = 0x0207
	ID_DATA_HASH_3 = 0x0208
)

//

var EI map[uint32]Ezei = map[uint32]Ezei{
	ID_MAGIC:        {"Magic", ET_MASTER, EC_STRUCT},
	ID_NULL:         {"Null", ET_BINARY, EC_STRUCT},
	ID_DATA:         {"Data", ET_BINARY, EC_DATA},
	ID_META_DATA:    {"MetaData", ET_BINARY, EC_META},
	ID_META_LIST:    {"MetaList", ET_MASTER, EC_HINT},
	ID_BLOCK_SIZE:   {"BlockSize", ET_UINT64, EC_HINT},
	ID_BLOCK_DATA:   {"BlockData", ET_UINT64, EC_HINT},
	ID_BLOCK_PARITY: {"BlockParity", ET_UINT64, EC_HINT},
	ID_CHECK_SUM:    {"CheckSum", ET_BINARY, EC_HINT},
	ID_PARITY:       {"Parity", ET_BINARY, EC_HINT},
	ID_VOID:         {"Void", ET_BINARY, EC_STRUCT},
	ID_PAD:          {"Pad", ET_BINARY, EC_STRUCT},
	ID_EOF:          {"Eof", ET_UINT64, EC_STRUCT},

	ID_SUITE:      {"Suite", ET_BINARY, EC_CIPHER},
	ID_KEK_SALT:   {"KekSalt", ET_BINARY, EC_CIPHER},
	ID_NONCE:      {"Nonce", ET_BINARY, EC_CIPHER},
	ID_NONCE_MASK: {"NonceMask", ET_BINARY, EC_CIPHER},
	ID_CEK:        {"Cek", ET_BINARY, EC_CIPHER},

	ID_POSITION:  {"Position", ET_UINT64, EC_META},
	ID_PATH:      {"Path", ET_BINARY, EC_META},
	ID_MODE:      {"Mode", ET_UINT64, EC_META},
	ID_SIZE:      {"Size", ET_UINT64, EC_META},
	ID_SIZE_ENC:  {"SizeEnc", ET_UINT64, EC_META},
	ID_HASH:      {"Hash", ET_BINARY, EC_META},
	ID_HASH_META: {"HashMeta", ET_BINARY, EC_META},
	ID_MTIME:     {"Mtime", ET_UINT64, EC_META},
	ID_MTIME_NS:  {"MtimeNs", ET_UINT64, EC_META},
	ID_SIGNATURE: {"Signature", ET_BINARY, EC_META},

	ID_DEVICE:   {"Device", ET_UINT64, EC_META},
	ID_INODE:    {"Inode", ET_UINT64, EC_META},
	ID_NLINK:    {"Nlink", ET_UINT64, EC_META},
	ID_UID:      {"Uid", ET_UINT64, EC_META},
	ID_GID:      {"Gid", ET_UINT64, EC_META},
	ID_MAJOR:    {"Major", ET_UINT64, EC_META},
	ID_MINOR:    {"Minor", ET_UINT64, EC_META},
	ID_ATIME:    {"Atime", ET_UINT64, EC_META},
	ID_ATIME_NS: {"AtimeNs", ET_UINT64, EC_META},
	ID_CTIME:    {"Ctime", ET_UINT64, EC_META},
	ID_CTIME_NS: {"CtimeNs", ET_UINT64, EC_META},
	ID_SYMLINK:  {"Symlink", ET_BINARY, EC_META},
	ID_EX_ATTR:  {"ExAttr", ET_BINARY, EC_META},

	ID_BTIME:    {"Btime", ET_UINT64, EC_META},
	ID_BTIME_NS: {"BtimeNs", ET_UINT64, EC_META},

	ID_VERSION_INFO:      {"VersionInfo", ET_BINARY, EC_INFO},
	ID_ARCHIVE_INFO:      {"ArchiveInfo", ET_BINARY, EC_INFO},
	ID_ENCRYPT_INFO:      {"EncryptInfo", ET_BINARY, EC_INFO},
	ID_COMPRESS_INFO:     {"CompressInfo", ET_BINARY, EC_INFO},
	ID_HASH_INFO:         {"HashInfo", ET_BINARY, EC_INFO},
	ID_MAC_INFO:          {"MacInfo", ET_BINARY, EC_INFO},
	ID_SIGN_INFO:         {"SignInfo", ET_BINARY, EC_INFO},
	ID_ERASURE_CODE_INFO: {"ErasureCodeInfo", ET_BINARY, EC_INFO},
	ID_AUTHOR_INFO:       {"AuthorInfo", ET_BINARY, EC_INFO},
	ID_TIME_INFO:         {"TimeInfo", ET_BINARY, EC_INFO},
	ID_TIMEN_INFO:        {"TimenInfo", ET_BINARY, EC_INFO},
	ID_OS_INFO:           {"OsInfo", ET_BINARY, EC_INFO},
	ID_FS_INFO:           {"FsInfo", ET_BINARY, EC_INFO},

	ID_EXTRA_DATA:  {"ExtraData", ET_BINARY, EC_DATA},
	ID_SIZE_2:      {"Size2", ET_UINT64, EC_META},
	ID_HASH_2:      {"Hash2", ET_BINARY, EC_META},
	ID_DATA_SIZE_2: {"DataSize2", ET_UINT64, EC_META},
	ID_DATA_HASH_2: {"DataHash2", ET_BINARY, EC_META},
	ID_SIZE_3:      {"Size3", ET_UINT64, EC_META},
	ID_HASH_3:      {"Hash3", ET_BINARY, EC_META},
	ID_DATA_SIZE_3: {"DataSize3", ET_UINT64, EC_META},
	ID_DATA_HASH_3: {"DataHash3", ET_BINARY, EC_META},
}
