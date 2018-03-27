//
//
// +build windows

package main

import (
	"os"
	"path/filepath"
	"time"
)

//

func cleanPath(p string) string {
	// path := filepath.ToSlash(filepath.Clean(p))
	path := filepath.ToSlash(p)
	l := len(filepath.VolumeName(path))
	return path[l:]
}

//

const (
	SYSCALL_O_NOATIME = 0
)

//

func lChtimes(name string, atime time.Time, mtime time.Time) (err error) {
	return os.Chtimes(name, atime, mtime)
}

//

func lockFile(f *os.File, exclusive bool) (err error) {
	return
}

//

func getMetaDataSys(m *Meta, path string, fi os.FileInfo) error {
	return nil
}

//

const (
	SIZE_EXATTR = 64
)

//

func EncodeMetaSys(o *[]byte, ci *CipherInfo, m *Meta) {
}

//

func FinalizeFileSys(ci *CipherInfo, meta *Meta) (err error) {
	// mode := os.FileMode(meta.Mode)

	mtime := time.Unix(meta.Mtime, meta.MtimeNs)
	atime := time.Unix(meta.Atime, meta.AtimeNs)
	err = lChtimes(meta.PathDst, atime, mtime)
	if err != nil {
		eMsg(E_INFO, err, "%s", meta.PathDst)
		err = nil
	}

	return
}
