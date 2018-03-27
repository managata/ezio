//
//
// +build linux

package main

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//

func cleanPath(p string) string {
	return p
	// return filepath.Clean(p)
}

//

const (
	SYSCALL_O_NOATIME = syscall.O_NOATIME
)

//

func getRdevMajor(rdev uint64) uint64 {
	return uint64((rdev >> 8) & 0xfff)
}

//

func getRdevMinor(rdev uint64) uint64 {
	return uint64((rdev & 0xff) | ((rdev >> 12) & 0xfff00))
}

//

func getRdev(major uint64, minor uint64) uint64 {
	return (major << 8) | (minor & 0xff) | ((minor & 0xfff00) << 12)
}

//

const (
	AT_FDCWD            uint = 0xFFFFFFFFFFFFFF9C
	AT_SYMLINK_NOFOLLOW      = 0x100
)

//

func lChtimes(name string, atime time.Time, mtime time.Time) (err error) {
	var utimes [2]syscall.Timespec
	utimes[0] = syscall.NsecToTimespec(atime.UnixNano())
	utimes[1] = syscall.NsecToTimespec(mtime.UnixNano())

	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(name)
	if err != nil {
		return
	}
	_, _, ierr := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(AT_FDCWD), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer((*[2]syscall.Timespec)(unsafe.Pointer(&utimes[0])))), uintptr(AT_SYMLINK_NOFOLLOW), 0, 0)
	if ierr == 0 {
		return nil
	}
	return err
}

//

func lockFile(f *os.File, exclusive bool) (err error) {
	t := syscall.F_RDLCK
	if exclusive {
		t = syscall.F_WRLCK
	}
	flockT := syscall.Flock_t{
		Type:   int16(t),
		Whence: io.SeekStart,
		Start:  0,
		Len:    0,
	}

	err = syscall.FcntlFlock(f.Fd(), syscall.F_SETLKW, &flockT)
	return
}

//

func getMetaDataSys(m *Meta, path string, fi os.FileInfo) error {
	// linux
	var s syscall.Stat_t
	syscall.Lstat(path, &s)
	m.Device = s.Dev
	m.Inode = s.Ino
	m.Nlink = s.Nlink
	m.Uid = int64(s.Uid)
	m.Gid = int64(s.Gid)
	m.Major = getRdevMajor(s.Rdev)
	m.Minor = getRdevMinor(s.Rdev)
	m.Atime, m.AtimeNs = s.Atim.Unix()
	m.Ctime, m.CtimeNs = s.Ctim.Unix()

	// symlink
	if fi.Mode()&os.ModeType == os.ModeSymlink {
		spath, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if len(spath) == 0 {
			return os.ErrInvalid
		}
		m.Symlink = spath
	}

	// extended attribute
	exAttr = exAttr[:0]
	if fi.Mode()&os.ModeType != os.ModeSymlink {
		getExAttr(path, &exAttr)
	}
	m.ExAttr = exAttr

	return nil
}

//

const (
	SIZE_EXATTR = 1048576
)

var eaL []byte = make([]byte, SIZE_EXATTR, SIZE_EXATTR)
var eaB []byte = make([]byte, SIZE_EXATTR, SIZE_EXATTR)

//

func getExAttr(path string, exattr *[]byte) {
	eaL = eaL[:SIZE_EXATTR]
	eaB = eaB[:SIZE_EXATTR]

	n, err := syscall.Listxattr(path, eaL)
	if err != nil {
		eMsg(E_ERR, nil, "can not get Extended Attributes")
		return
	}
	if n == SIZE_EXATTR {
		eMsg(E_ERR, nil, "Extended Attributes are too large")
		return
	}
	eaL = eaL[:n]

	ll := strings.Split(string(eaL), "\000")

	for _, v := range ll {
		if len(v) == 0 {
			break
		}
		eaL = eaL[:SIZE_EXATTR]
		eaB = eaB[:SIZE_EXATTR]
		n, _ := syscall.Getxattr(path, v, eaL)
		eaL = eaL[:n]
		base64.StdEncoding.Encode(eaB, eaL)
		eaB = eaB[:base64.StdEncoding.EncodedLen(len(eaL))]
		*exattr = append(*exattr, []byte(v)...)
		*exattr = append(*exattr, '\000')
		*exattr = append(*exattr, eaB...)
		*exattr = append(*exattr, '\000')
	}

}

//

func setExAttr(path string, exattr []byte) {
	ll := strings.Split(string(exattr), "\000")

	for i := 0; i < len(ll); i += 2 {
		k := ll[i]
		if len(k) == 0 {
			break
		}
		v, _ := base64.StdEncoding.DecodeString(ll[i+1])

		syscall.Setxattr(path, k, v, 0)
	}
}

//

func EncodeMetaSys(o *[]byte, ci *CipherInfo, m *Meta) {
	EncodeMetaU(o, ID_DEVICE, uint64(m.Device))
	EncodeMetaU(o, ID_INODE, uint64(m.Inode))
	EncodeMetaU(o, ID_NLINK, uint64(m.Nlink))
	EncodeMetaU(o, ID_UID, uint64(m.Uid))
	EncodeMetaU(o, ID_GID, uint64(m.Gid))
	EncodeMetaU(o, ID_MAJOR, uint64(m.Major))
	EncodeMetaU(o, ID_MINOR, uint64(m.Minor))
	EncodeMetaU(o, ID_ATIME, uint64(m.Atime))
	EncodeMetaU(o, ID_ATIME_NS, uint64(m.AtimeNs))
	EncodeMetaU(o, ID_CTIME, uint64(m.Ctime))
	EncodeMetaU(o, ID_CTIME_NS, uint64(m.CtimeNs))
	if len(m.Symlink) != 0 {
		EncodeMetaB(o, ID_SYMLINK, []byte(m.Symlink))
	}
	if len(m.ExAttr) != 0 {
		EncodeMetaB(o, ID_EX_ATTR, m.ExAttr)
	}
}

//

func FinalizeFileSys(ci *CipherInfo, meta *Meta) (err error) {
	mode := os.FileMode(meta.Mode)

	switch mode & os.ModeType {
	case os.ModeNamedPipe:
		err = syscall.Mkfifo(meta.PathDst, 0600)
	case os.ModeSocket:
		eMsg(E_ERR, nil, "socket can not extract")
	case os.ModeDevice:
		m := uint32(syscall.S_IFBLK)
		if mode&os.ModeCharDevice == os.ModeCharDevice {
			m = uint32(syscall.S_IFCHR)
		}
		syscall.Mknod(meta.PathDst, m, int(getRdev(meta.Major, meta.Minor)))
	}

	mtime := time.Unix(meta.Mtime, meta.MtimeNs)
	atime := time.Unix(meta.Atime, meta.AtimeNs)
	//    err = os.Chtimes(meta.PathDst, atime, mtime)
	err = lChtimes(meta.PathDst, atime, mtime)
	if err != nil {
		eMsg(E_INFO, err, "%s", meta.PathDst)
		err = nil
	}

	if (meta.Uid != -1) && (meta.Gid != -1) {
		err = os.Lchown(meta.PathDst, int(meta.Uid), int(meta.Gid))
		if err != nil {
			eMsg(E_INFO, err, "")
			err = nil
		}
	}

	if mode&os.ModeType != os.ModeSymlink {
		err = os.Chmod(meta.PathDst, os.FileMode(meta.Mode))
		if err != nil {
			eMsg(E_WARN, err, "%s", meta.PathDst)
		}

		setExAttr(meta.PathDst, meta.ExAttr)
	}

	return
}
