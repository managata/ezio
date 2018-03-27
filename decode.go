//
//
//

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

type Dir struct {
	PathDst string
	Mtime   int64
	MtimeNs int64
	Atime   int64
	AtimeNs int64
}

var (
	errNotError          = errors.New("!")
	errNotErrorButDicard = errors.New("@")
)

var dirList = make([]Dir, 0, 128)

// L1 func

//
func ExtractFilm(ar *Reader, ci *CipherInfo) (err error) {
	dB(nil, "# ExtractFilm")

	meta := Meta{Uid: -1, Gid: -1, Hash: hashRaw[:0], HashDec: hashDec[:0], HashMeta: hashMeta[:0], Signature: sigNature[:0], ExAttr: exAttr[:0]}
	setMTmp(0)

	_, err = SearchMark(ar)
	if err != nil {
		if err == io.EOF {
			return
		}
		eMsg(E_CRIT, nil, "magic word not found any more")
	}

	for {
		var id uint32
		id, _, err = PeekElementId(ar)
		dB(nil, "next element: id=%x(%s)", id, EI[id].Name)
		if err != nil {
			return
		}

		switch EI[id].Category {
		case EC_NULL:
			err = errors.New("null category element")
		case EC_STRUCT:
			err = DecodeStruct(ar, ci, &meta)
		case EC_DATA:
			err = DecodeData(ar, ci, &meta)
		case EC_CIPHER:
			err = DecodeCipher(ar, ci)
		case EC_META:
			err = DecodeMeta(ar, ci, &meta)
		case EC_HINT:
			err = DecodeHint(ar)
			return err
		case EC_INFO:
		default:
			eMsg(E_WARN, nil, " undefined element id")
			DiscardElement(ar)
		}

		if err != nil {
			return
		}
	}

	return
}

// L2 func

//
func SearchMark(ar *Reader) (size uint64, err error) {
	dB(nil, "* SearchMark:")
	var id uint32
	var b []byte

	b, err = ar.Peek(1)
	if err != nil {
		return
	}

	id, _, err = PeekElementId(ar)
	dB(nil, "  SearchMark:  peek id=%x(%s) pos=%x err=%s", id, EI[id].Name, ar.Position(), err)
	if err == nil {
		if id == ID_MAGIC {
			_, size, _, err = ReadElementM(ar)
			return size, err
		}
	}

	eMsg(E_WARN, nil, "structure damaged. some files may be skipped.")

	for {
		_, err = ar.ReadBytes(ID_MAGIC_1)
		if err != nil {
			return 0, err
		}

		b, err = ar.Peek(1)
		if err != nil {
			return 0, err
		}
		if b[0] != ID_MAGIC_2 {
			continue
		}

		_, err = ar.ReadByte()
		if err != nil {
			return 0, err
		}
		size, _, err = ReadElementSize(ar)
		if err != nil {
			return 0, err
		}
		return size, nil
	}

	return 0, errors.New("strange error in SearchMark")
}

//

func DecodeStruct(ar *Reader, ci *CipherInfo, meta *Meta) (err error) {
	dB(nil, "* DecodeStruct:")

	var id uint32
	id, _, err = PeekElementId(ar)
	if err != nil {
		return err
	}

	if id == ID_MAGIC {
		return errors.New("unexpected new film")
	}

	id, _, err = ReadElementB(ar, &gTmp)
	if err != nil {
		return err
	}

	switch id {
	case ID_EOF:
		if oP.View || oP.List {
			updateMetaList(meta)
			return errNotError
		}
		err = FinalizeFile(ci, meta)
		if err != nil {
			eMsg(E_ERR, err, "")
		}
		return errNotError
	case ID_NULL:
		eMsg(E_WARN, nil, "ID_NULL appeared")
	case ID_VOID:
	case ID_PAD:
		_, err = DiscardFilm(ar)
		if err == nil {
			err = errNotError
		}
	}

	return err
}

//

func DecodeData(ar *Reader, ci *CipherInfo, meta *Meta) (err error) {
	dB(nil, "* DecodeData:")
	// gTmp2 -> decrypt -> unzip -> hash
	//                          -> write

	if oP.View || oP.List {
		if ci.Suite[CS_AEAD] != AEAD_NONE {
			IncrementNonce(ci)
		}
		_, _, _, err = DiscardElement(ar)
		return err
	}

	// metadata check
	if len(meta.Path) == 0 {
		return errors.New("Data before ID_PATH")
	}

	// regular file check
	if !os.FileMode(meta.Mode).IsRegular() {
		return errors.New("only regular file can contain Data")
	}

	var f *os.File
	var bw *bufio.Writer
	if oP.Test {
		bw = bufio.NewWriter(ioutil.Discard)
	} else if oP.StdOut {
		bw = bufio.NewWriter(os.Stdout)
	} else {
		meta.PathDst = getPathDst(oP.ExtractDir, meta.Path)
		dB(nil, "  DecodeData: PathDst=%s", meta.PathDst)

		// dir check
		dir := filepath.Dir(meta.PathDst)
		if !isDirPresent(dir) {
			err = os.MkdirAll(dir, 0777)
			if err != nil {
				eMsg(E_ERR, err, "'%s'", dir)
				return err
			}
		}

		// path check
		if isLpathPresent(meta.PathDst) {
			if oP.Overwrite {
				err := os.RemoveAll(meta.PathDst)
				if err != nil {
					return err
				}
			} else {
				err = os.ErrExist
				return err
			}
		}

		// // hardlink
		// if (meta.Nlink > 1) && makeHardLink(meta) {
		// 	_, err = DiscardFilm(ar)
		// 	return err
		// }

		// path create
		f, err = os.OpenFile(meta.PathDst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			f.Close()
			eMsg(E_ERR, err, "'%s'", meta.PathDst)
			return err
		}
		err = lockFile(f, true)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
		bw = bufio.NewWriter(f)
	}

	// hash
	hash_w := NewHash(ci)()

	// multi write
	hash_bw_w := io.MultiWriter(hash_w, bw)

	// unzip
	zip_r, zip_w := io.Pipe()
	//	defer zip_w.Close()

	//	var unzip_r io.ReadCloser

	// wait goroutine
	wc := make(chan bool)
	closed := false
	defer func() {
		f.Close()
		bw.Flush()
		zip_w.Close()
		if !closed {
			wc <- true
		}
	}()

	go UnZip(ci, hash_bw_w, zip_r, wc)

	// read
	nid := uint32(ID_DATA)
	for nid == ID_DATA {
		_, _, err = ReadElementB(ar, &gTmp2)
		if err != nil {
			return err
		}

		// decrypt
		if ci.Suite[CS_AEAD] == AEAD_NONE {
			zip_w.Write(gTmp2)
		} else {
			err = DecryptBinary(&gTmp, gTmp2, ci, false)
			if err != nil {
				return err
			}
			zip_w.Write(gTmp)
		}

		nid, _, err = PeekElementId(ar)
		if err != nil {
			return err
		}
	}

	zip_w.Close()
	wc <- true
	closed = true

	meta.HashDec = append(meta.HashDec[:0], hash_w.Sum(nil)...)

	bw.Flush()
	f.Close()

	return nil
}

//

func DecodeCipher(ar *Reader, ci *CipherInfo) (err error) {
	var id uint32
	id, _, err = ReadElementB(ar, &gTmp)
	dB(nil, "* DecodeCipher: id=%x(%s) b[%x] err=%s", id, EI[id].Name, len(gTmp), err)
	if err != nil {
		return err
	}

	switch id {
	case ID_SUITE:
		copy(ci.Suite, gTmp[:SIZE_SUITE])
	case ID_KEK_SALT:
		if len(gTmp) != GetHashSize(ci) {
			err = errors.New("Salt size invalid")
			return err
		}
		ci.KekSalt = append(ci.KekSalt[:0], gTmp...)
		if (ci.DecryptKey == nil) && (len(ci.Kek) == 0) {
			GenerateKek(ci)
			ErasePass(ci, false)
		}
	case ID_NONCE:
		copy(ci.Nonce, gTmp[:SIZE_NONCE])
	case ID_NONCE_MASK:
		ci.NonceMask = binary.BigEndian.Uint64(gTmp[:SIZE_NONCE_MASK])
	case ID_CEK:
		dB(nil, "  suite[%x] %x", len(ci.Suite), ci.Suite)
		dB(nil, "  password[%x] %x", len(ci.Pass), ci.Pass)
		dB(nil, "  kekSalt[%x] %x", len(ci.KekSalt), ci.KekSalt)
		dB(nil, "  kek[%x] %x", len(ci.Kek), ci.Kek)
		dB(nil, "  nonceMask %x", ci.NonceMask)
		dB(nil, "  nonce[%x] %x", len(ci.Nonce), ci.Nonce)
		err = DecryptBinary(&ci.Cek, gTmp, ci, true)
		if err != nil {
			return err
		}
		dB(nil, "  cek[%x] %x", len(ci.Cek), ci.Cek)
	}

	return nil
}

//

func DecodeMeta(ar *Reader, ci *CipherInfo, meta *Meta) (err error) {
	var id uint32
	id, _, err = PeekElementId(ar)
	dB(nil, "* DecodeMeta: id=%x(%s)", id, EI[id].Name)

	// plain
	if id != ID_META_DATA {
		_, err = DecodeMetaElement(ar, ci, meta)
		return err
	}

	// encrypted
	_, _, err = ReadElementB(ar, &gTmp)
	if err != nil {
		return err
	}
	err = DecryptBinary(&gTmp2, gTmp, ci, false)
	if err != nil {
		return err
	}

	bbt := NewReader(bytes.NewReader(gTmp2))

	for m, l := 0, len(gTmp2); m < l; {
		x, err := DecodeMetaElement(bbt, ci, meta)
		if err != nil {
			return err
		}
		m += int(x)
		dB(nil, "  DecodeMeta: size=%x done=%x this=%x", l, m, x)
	}

	return nil
}

//

func DecodeMetaElement(ar *Reader, ci *CipherInfo, meta *Meta) (n int64, err error) {
	var u uint64
	var id uint32

	id, _, err = PeekElementId(ar)
	if err != nil {
		return 0, err
	}
	if EI[id].Type == ET_UINT64 {
		_, u, n, err = ReadElementU(ar)
		dB(nil, "* DecodeMetaElement: id=%x(%s) u=%x err=%s", id, EI[id].Name, u, err)
		if !oP.List {
			l := len(mTmp)
			setMTmp(l + 8)
			binary.BigEndian.PutUint64(mTmp[l:], u)
		}
	} else {
		_, n, err = ReadElementB(ar, &gTmp)
		dB(nil, "* DecodeMetaElement: id=%x(%s) b[%x] err=%s", id, EI[id].Name, len(gTmp), err)
		if !oP.List {
			if id != ID_HASH_META {
				mTmp = append(mTmp, gTmp...)
			}
		}
	}
	if err != nil {
		return n, err
	}

	switch id {
	case ID_POSITION:
		meta.Position = int64(u)
	case ID_PATH:
		meta.Path = string(gTmp)
		if (oP.ExcludeReg != nil) && oP.ExcludeReg.MatchString(meta.Path) {
			return n, errNotErrorButDicard
		}
		if (oP.IncludeReg != nil) && !oP.IncludeReg.MatchString(meta.Path) {
			return n, errNotErrorButDicard
		}
		if oP.Extract || oP.Test {
			eMsg(E_PATH, nil, "%s", meta.Path)
		}
	case ID_MODE:
		meta.Mode = uint32(u)
	case ID_SIZE:
		meta.Size = int64(u)
	case ID_SIZE_ENC:
		meta.SizeEnc = int64(u)
	case ID_HASH:
		if len(gTmp) != cap(meta.Hash) {
			err = errors.New("hash size invalid")
		}
		meta.Hash = append(meta.Hash[:0], gTmp...)
	case ID_HASH_META:
		if len(gTmp) != cap(meta.HashMeta) {
			err = errors.New("hash(meta) size invalid")
		}
		meta.HashMeta = append(meta.HashMeta[:0], gTmp...)
	case ID_MTIME:
		meta.Mtime = int64(u)
	case ID_MTIME_NS:
		meta.MtimeNs = int64(u)
	case ID_SIGNATURE:
		meta.Signature = append(meta.Signature[:0], gTmp...)
	case ID_DEVICE:
		meta.Device = uint64(u)
	case ID_INODE:
		meta.Inode = uint64(u)
	case ID_NLINK:
		meta.Nlink = uint64(u)
	case ID_UID:
		meta.Uid = int64(u)
	case ID_GID:
		meta.Gid = int64(u)
	case ID_MAJOR:
		meta.Major = uint64(u)
	case ID_MINOR:
		meta.Minor = uint64(u)
	case ID_ATIME:
		meta.Atime = int64(u)
	case ID_ATIME_NS:
		meta.AtimeNs = int64(u)
	case ID_CTIME:
		meta.Ctime = int64(u)
	case ID_CTIME_NS:
		meta.CtimeNs = int64(u)
	case ID_SYMLINK:
		meta.Symlink = string(gTmp)
	case ID_EX_ATTR:
		meta.ExAttr = append(meta.ExAttr[:0], gTmp...)
	case ID_BTIME:
		meta.Btime = int64(u)
	case ID_BTIME_NS:
		meta.BtimeNs = int64(u)
	default:
		eMsg(E_WARN, nil, "element id not supported: %x", id)
	}

	return n, nil
}

//

func DecodeHint(ar *Reader) (err error) {
	var id uint32
	id, _, err = PeekElementId(ar)
	if err != nil {
		return err
	}
	dB(nil, "* DecodeHint: id=%x(%s)", id, EI[id].Name)

	_, err = DiscardFilm(ar)
	return err
}

//

func DecodeInfo(ar *Reader) (err error) {
	var id uint32
	id, _, err = PeekElementId(ar)
	if err != nil {
		return err
	}
	dB(nil, "* DecodeInfo: id=%x(%s)", id, EI[id].Name)

	_, _, err = ReadElementB(ar, &gTmp)
	if err != nil {
		return err
	}

	eMsg(E_INFO, nil, "* DecodeInfo: %s", string(gTmp))
	return err
}

// L3.. func

//
func FinalizeFile(ci *CipherInfo, meta *Meta) (err error) {
	dB(nil, "- Finalize: %#v", meta)

	hm := NewHash(ci)()
	hm.Write(mTmp)
	hashMetaDec := hm.Sum(nil)
	if !bytes.Equal(meta.HashMeta, hashMetaDec) {
		err = errors.New("meta data corrupted")
		return err
	}

	mode := os.FileMode(meta.Mode)

	if mode.IsRegular() && !bytes.Equal(meta.Hash, meta.HashDec) {
		if !(oP.Test || oP.StdOut) {
			err = os.Remove(meta.PathDst)
			if err != nil {
				eMsg(E_WARN, err, "")
			}
		}
		err = errors.New("file data corrupted")
		return err
	}

	if mode.IsRegular() && (ci.VerifyKey != nil) {
		if !VerifyHash(meta.Hash, meta.Signature, ci) {
			if !oP.Test {
				err = os.Remove(meta.PathDst)
				if err != nil {
					eMsg(E_WARN, err, "")
				}
			}
			err = errors.New("signature verification failed")
			return err
		} else {
			eMsg(E_NOTICE, nil, "signature verified")
		}
	}

	if oP.Test || oP.StdOut {
		return nil
	}

	if len(meta.PathDst) == 0 {
		meta.PathDst = getPathDst(oP.ExtractDir, meta.Path)
	}

	if isLpathPresent(meta.PathDst) && !mode.IsRegular() && !mode.IsDir() {
		if oP.Overwrite {
			err := os.Remove(meta.PathDst)
			if err != nil {
				eMsg(E_ERR, err, "%s", meta.PathDst)
				return nil
			}
		} else {
			eMsg(E_ERR, err, "%s: already exist. skip.", meta.PathDst)
			return os.ErrExist
		}
	}

	if (meta.Nlink > 1) && !mode.IsDir() {
		if makeHardLink(meta) {
			return nil
		}
	}

	switch mode & os.ModeType {
	case os.ModeDir:
		err = os.MkdirAll(meta.PathDst, 0700)
	case os.ModeSymlink:
		err = os.Symlink(meta.Symlink, meta.PathDst)
	}

	err = FinalizeFileSys(ci, meta)
	if err != nil {
		return
	}

	if mode.IsDir() {
		updateDirList(meta)
	}

	return err
}

//

func SearchMetaList(ar *Reader) bool {
	// MetaList must be last or last-2 film of archive

	ar.Seek(-10, io.SeekEnd)

	for i := 0; i < 3; i++ {
		id, u, n, err := ReadElementU(ar)
		if (n != 10) || (id != ID_EOF) {
			return false
		}
		pos, err := ar.Seek(0-int64(u)-10, io.SeekCurrent)
		if err != nil {
			return false
		}
		id, _, _, err = ReadElementM(ar)
		if (err != nil) || (id != ID_MAGIC) {
			return false
		}

		found := false
		for true {
			id, _, err := PeekElementId(ar)
			if err != nil {
				return false
			}
			if (id == ID_EOF) || (id == ID_MAGIC) {
				break
			}
			if id == ID_META_LIST {
				found = true
				break
			}
			DiscardElement(ar)
		}

		if found {
			_, err = ar.Seek(pos, io.SeekStart)
			if err != nil {
				return false
			}
			return true
		}

		pos, err = ar.Seek(pos-10, io.SeekStart)
		if err != nil {
			return false
		}
	}

	return false
}

//

func ExtractMetaList(ar *Reader, ci *CipherInfo) bool {
	defer ar.Seek(0, io.SeekStart)

	if !SearchMetaList(ar) {
		eMsg(E_INFO, nil, "MetaList block not found")
		return false
	}
	eMsg(E_INFO, nil, "MetaList block found!")

	meta := Meta{Position: -1}
	var id uint32
	var n int64
	var err error

	id, _, n, err = ReadElementM(ar)
	if (n < 0) || (id != ID_MAGIC) {
		return false
	}

	for fin := false; !fin; {
		id, n, err = PeekElementId(ar)
		dB(nil, "next element: id=%x(%s)", id, EI[id].Name)
		if err != nil {
			return false
		}

		switch EI[id].Category {
		case EC_NULL:
			eMsg(E_WARN, nil, "null category element")
			continue
		case EC_STRUCT:
			if id == ID_EOF {
				DiscardElement(ar)
				updateMetaList(&meta)
				return true
			}
			if id == ID_VOID {
				DiscardElement(ar)
				continue
			}
			return false
		case EC_DATA:
			return false
		case EC_CIPHER:
			err = DecodeCipher(ar, ci)
			if err != nil {
				eMsg(E_ERR, err, "")
				return false
			}
			continue
		case EC_META:
			err = DecodeMeta(ar, ci, &meta)
			if err != nil {
				eMsg(E_ERR, err, "")
				return false
			}
			continue
		case EC_HINT:
			if id == ID_META_LIST {
				if (len(meta.Path) > 0) && !(meta.Position < 0) {
					appendMetaList(&meta)
				}
				DiscardElement(ar)
				continue
			}
		case EC_INFO:
		default:
			eMsg(E_WARN, nil, " undefined element id")
			continue
		}

	}

	return true
}

//

func updateDirList(meta *Meta) {
	d := Dir{meta.PathDst, meta.Mtime, meta.MtimeNs, meta.Atime, meta.AtimeNs}
	dirList = append(dirList, d)
	dB(nil, "- dirList: %s", meta.Path)
}

//

func RestoreDirTime() {
	if len(dirList) == 0 {
		return
	}

	for _, d := range dirList {
		mtime := time.Unix(d.Mtime, d.MtimeNs)
		atime := time.Unix(d.Atime, d.AtimeNs)
		err := lChtimes(d.PathDst, atime, mtime)
		if err != nil {
			eMsg(E_WARN, err, "%s", d.PathDst)
		} else {
			eMsg(E_INFO, nil, "'%s' restoring", d.PathDst)
		}
	}
}

//

func DecryptBinary(pt *[]byte, ct []byte, ci *CipherInfo, kek bool) error {
	dB(nil, "- DecryptBinary: ct[%x]", len(ct))

	if kek && (ci.DecryptKey != nil) {
		h := sha512.New()
		IncrementNonce(ci)
		p, err := rsa.DecryptOAEP(h, rand.Reader, ci.DecryptKey.(*rsa.PrivateKey), ct, ci.Nonce)
		*pt = append((*pt)[:0], p...)
		return err
	}

	e, err := NewAead(ci, kek)
	if err != nil {
		return err
	}

	IncrementNonce(ci)
	nonce := ct[:e.NonceSize()]
	if !bytes.Equal(ci.Nonce, nonce) {
		return errors.New("DecryptBinary: nonce invalid")
	}

	*pt = (*pt)[:0]
	*pt, err = e.Open(*pt, nonce, ct[e.NonceSize():], nil)
	if err != nil {
		return err
	}

	dB(nil, "  DecryptBinary: pt[%x]", len(*pt))

	return nil
}

// hard link

type pH struct {
	path string
	hash []byte
}

//

var devInode map[[2]uint64]pH = make(map[[2]uint64]pH, 128)

//

func makeHardLink(meta *Meta) bool {
	dB(nil, "- makeHardLink:")

	ph, ok := devInode[[2]uint64{meta.Device, meta.Inode}]
	if !ok {
		dB(nil, "  makeHardLink: not found")
		hash := make([]byte, len(meta.Hash))
		copy(hash, meta.Hash)
		devInode[[2]uint64{meta.Device, meta.Inode}] = pH{path: meta.Path, hash: hash}
		return false
	}

	dB(nil, "  makeHardLink: [%d]%x [%d]%x\n", len(meta.Hash), meta.Hash, len(ph.hash), ph.hash)
	if !bytes.Equal(meta.Hash, ph.hash) {
		eMsg(E_INFO, nil, "makeHardLink: found but hash not match")
		return false
	}

	if isLpathPresent(meta.PathDst) {
		err := os.RemoveAll(meta.PathDst)
		if err != nil {
			return false
		}
	}

	o := getPathDst(oP.ExtractDir, ph.path)
	err := os.Link(o, meta.PathDst)
	if err != nil {
		eMsg(E_ERR, err, "'%s'", meta.PathDst)
		return false
	}
	return true
}

//

func getPathDst(d string, p string) string {
	return filepath.Join(d, cleanPath(p))
}

// erasure code

func SearchErasureCode(ar *Reader) (f bool, pos int64) {
	// ErasureCode must be last of archive
	var err error
	var id uint32
	var u uint64
	var n int64

	ar.Seek(-10, io.SeekEnd)

	for i := 0; i < 1; i++ {
		id, u, n, err = ReadElementU(ar)
		if (n != 10) || (id != ID_EOF) {
			return
		}
		pos, err = ar.Seek(0-int64(u)-10, io.SeekCurrent)

		if err != nil {
			return
		}
		id, _, _, err = ReadElementM(ar)
		if (err != nil) || (id != ID_MAGIC) {
			return
		}

		found := false
		for true {
			id, _, err := PeekElementId(ar)
			if err != nil {
				return
			}
			if (id == ID_EOF) || (id == ID_MAGIC) {
				break
			}
			if id == ID_BLOCK_SIZE {
				found = true
				break
			}
			DiscardElement(ar)
		}

		if found {
			_, err = ar.Seek(pos, io.SeekStart)
			if err != nil {
				return
			}
			f = true
			return
		}

		pos, err = ar.Seek(pos-10, io.SeekStart)
		if err != nil {
			return
		}
	}

	return
}

//

func updateMetaList(meta *Meta) {
	m := Meta(*meta)

	m.Hash = make([]byte, len(meta.Hash))
	copy(m.Hash, meta.Hash)

	m.HashMeta = make([]byte, len(meta.HashMeta))
	copy(m.HashMeta, meta.HashMeta)

	m.Signature = make([]byte, len(meta.Signature))
	copy(m.Signature, meta.Signature)

	m.ExAttr = make([]byte, len(meta.ExAttr))
	copy(m.ExAttr, meta.ExAttr)

	metaList = append(metaList, m)
	dB(nil, "- updateMetaList: %x, %s", meta.Position, meta.Path)
}
