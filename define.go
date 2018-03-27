//
//
//

package main

type Meta struct {
	// meta meta
	Position int64

	// common
	Path      string
	Mode      uint32
	Size      int64
	SizeEnc   int64
	Hash      []byte `json:",omitempty"`
	HashMeta  []byte `json:",omitempty"`
	Mtime     int64
	MtimeNs   int64
	Signature []byte `json:",omitempty"`

	// unix
	Device  uint64
	Inode   uint64
	Nlink   uint64
	Uid     int64
	Gid     int64
	Major   uint64
	Minor   uint64
	Atime   int64
	AtimeNs int64
	Ctime   int64
	CtimeNs int64
	Symlink string
	ExAttr  []byte `json:",omitempty"`

	//
	Btime   int64
	BtimeNs int64

	// encode
	PathSrc string `json:"-"`

	// decode
	PathTmp string `json:"-"`
	PathDst string `json:"-"`
	SizeDec int64  `json:"-"`
	HashDec []byte `json:"-"`

	//
	Hardlink string `json:"-"`
}

const ID_MAGIC_1 byte = 0x65
const ID_MAGIC_2 byte = 0x7a
const SIZE_UNKNOWN uint64 = 0xffffffffffffffff

const SIZE_BINARY_MAX int = 0x1000000

// Type
const (
	ET_NULL = iota
	ET_MASTER
	ET_UINT64
	ET_BINARY
)

// Category
const (
	EC_NULL = iota
	EC_STRUCT
	EC_DATA
	EC_CIPHER
	EC_META
	EC_HINT
	EC_INFO
)

// Max
const (
	EM_NULL   uint64 = 0
	EM_MASTER        = 0xff
	EM_UINT64        = 0xffffffffffffffff
	EM_BINARY        = 0xfffffffffffffe
)

// //
// type Ezei struct {
// 	Name     string
// 	Type     int
// 	Category int
// 	Min      uint64
// 	Max      uint64
// }

//
type Ezei struct {
	Name     string
	Type     int
	Category int
}
