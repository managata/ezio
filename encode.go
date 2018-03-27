//
//
//

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"os"
)

//

var metaList = make([]Meta, 0, 128)
var exAttr = make([]byte, SIZE_EXATTR)

//

var mTmp = make([]byte, 0, 1024*1024)
var gTmp = make([]byte, 0, SIZE_BINARY_MAX+1024*1024)
var gTmp2 = make([]byte, 0, SIZE_BINARY_MAX+1024*1024)

func setMTmp(l int) {
	mTmp = mTmp[:l]
}

func setGTmp(l int) {
	gTmp = gTmp[:l]
}

func setGTmp2(l int) {
	gTmp2 = gTmp2[:l]
}

// L1 func

//
func WriteFilm(pw *io.PipeWriter, ci *CipherInfo, path string, pos int64) (n int64, err error) {
	dB(nil, "# WriteFilm")

	if (oP.ExcludeReg != nil) && oP.ExcludeReg.MatchString(path) {
		return
	}
	if (oP.IncludeReg != nil) && !oP.IncludeReg.MatchString(path) {
		return
	}

	eMsg(E_PATH, nil, "%s", path)

	var fi os.FileInfo
	fi, err = os.Lstat(path)
	if err != nil {
		return
	}

	if fi.Mode()&os.ModeSocket == os.ModeSocket {
		eMsg(E_WARN, err, "file is socket, ignored")
		return
	}

	meta := Meta{Position: pos, Hash: hashRaw[:0], HashMeta: hashMeta[:0], ExAttr: exAttr[:0]}
	err = getMetaData(&meta, path, fi)
	if err != nil {
		return
	}
	setMTmp(0)

	//
	if fi.Mode().IsRegular() {
		flag := os.O_RDONLY
		if oP.NoAtime {
			//			flag |= syscall.O_NOATIME
			flag |= SYSCALL_O_NOATIME
		}
		var f *os.File
		f, err = os.OpenFile(meta.PathSrc, flag, 0600)
		f.Close()
		if err != nil {
			return
		}
	}

	//
	var l int64
	l, err = WriteMagic(pw)
	n += l
	if err != nil {
		return
	}

	// // WriteInfo()

	if oP.Encrypt {
		GenerateCek(ci)
	}
	l, err = WriteCipher(pw, ci)
	n += l
	if err != nil {
		return
	}

	l, err = WriteMeta(pw, ci, &meta)
	n += l
	if err != nil {
		return
	}

	if fi.Mode().IsRegular() {
		l, err = WriteData(pw, ci, &meta)
		n += l
		if err != nil {
			return
		}
	}

	l, err = WritePost(pw, ci, &meta)
	n += l
	if err != nil {
		return
	}

	l, err = WriteEof(pw, n)
	n += l
	if err != nil {
		return
	}

	appendMetaList(&meta)

	return
}

//

func WriteMetaList(pw *io.PipeWriter, ci *CipherInfo) (n int64, err error) {
	dB(nil, "# WriteMetaList")

	var l int64
	l, err = WriteMagic(pw)
	n += l
	if err != nil {
		return
	}

	if oP.Encrypt {
		GenerateCek(ci)
	}
	l, err = WriteCipher(pw, ci)
	n += l
	if err != nil {
		return
	}

	for _, m := range metaList {
		dB(nil, "  WriteMetaList: %d, %s", m.Position, m.Path)

		l, err = WriteElementM(pw, ID_META_LIST, SIZE_UNKNOWN)
		n += l
		if err != nil {
			return
		}

		l, err = WriteElementU(pw, ID_POSITION, uint64(m.Position))
		n += l
		if err != nil {
			return
		}

		setGTmp2(0)
		EncodeElementB(&gTmp2, ID_PATH, []byte(m.Path))
		EncodeElementU(&gTmp2, ID_MODE, uint64(m.Mode))
		EncodeElementU(&gTmp2, ID_SIZE, uint64(m.Size))
		EncodeElementU(&gTmp2, ID_SIZE_ENC, uint64(m.SizeEnc))
		EncodeElementU(&gTmp2, ID_MTIME, uint64(m.Mtime))

		if ci.Suite[CS_AEAD] == AEAD_NONE {
			l, err = WriteElement(pw, gTmp2)
			if err != nil {
				return
			}
		} else {
			err = EncryptBinary(&gTmp, gTmp2, ci, false)
			if err != nil {
				return
			}
			l, err = WriteElementB(pw, ID_META_DATA, gTmp)
			if err != nil {
				return
			}
		}

		n += l
	}

	l, err = WriteEof(pw, n)
	n += l

	return
}

//

func WritePad(pw *io.PipeWriter, c int) (n int64, err error) {
	dB(nil, "# WritePad: c=%d %x", c, c)

	var l int64
	l, err = WriteMagic(pw)
	n += l
	if err != nil {
		return
	}

	setGTmp(128)
	for i := 0; i < 128; i++ {
		gTmp[i] = byte(0)
	}

	c -= 2 + 1 + 1 + 1 + 8 // ezm:2+1 eof:1+1+8

	//	for c > 143 {
	for c > 0 {
		d := c
		if d > 143 {
			d = 128
		} else if d > 128 {
			d = 64
		}
		c -= d
		d -= 2 // pad:1+1+d

		l, err = WriteElementB(pw, ID_PAD, gTmp[:d])
		n += l
		if err != nil {
			return
		}
	}

	l, err = WriteEof(pw, n)
	n += l
	return
}

// L2 func

//
func WriteMagic(pw *io.PipeWriter) (n int64, err error) {
	dB(nil, "* WriteMagic")
	n, err = WriteElementM(pw, ID_MAGIC, SIZE_UNKNOWN)
	return
}

//

func WriteCipher(pw *io.PipeWriter, ci *CipherInfo) (n int64, err error) {
	dB(nil, "* WriteCipher")
	dB(nil, "  password[%x] %x", len(ci.Pass), ci.Pass)
	dB(nil, "  kekSalt[%x] %x", len(ci.KekSalt), ci.KekSalt)
	dB(nil, "  kek[%x] %x", len(ci.Kek), ci.Kek)
	dB(nil, "  nonceMask %x", ci.NonceMask)
	dB(nil, "  nonce[%x] %x", len(ci.Nonce), ci.Nonce)
	dB(nil, "  cek[%x] %x", len(ci.Cek), ci.Cek)

	var l int64

	// suite
	l, err = WriteElementB(pw, ID_SUITE, ci.Suite)
	n += l
	if err != nil {
		return
	}

	if !oP.Encrypt {
		return
	}

	// kek salt
	if len(ci.KekSalt) != 0 {
		l, err = WriteElementB(pw, ID_KEK_SALT, ci.KekSalt)
		n += l
		if err != nil {
			return
		}
	}

	// nonce mask
	setGTmp(SIZE_NONCE_MASK)
	binary.BigEndian.PutUint64(gTmp, ci.NonceMask)
	l, err = WriteElementB(pw, ID_NONCE_MASK, gTmp)
	n += l
	if err != nil {
		return
	}

	// nonce
	l, err = WriteElementB(pw, ID_NONCE, ci.Nonce)
	n += l
	if err != nil {
		return
	}

	// cek
	EncryptBinary(&gTmp, ci.Cek, ci, true)
	if err != nil {
		return
	}
	l, err = WriteElementB(pw, ID_CEK, gTmp)
	n += l

	dB(nil, "  en-cek[%x] %x", len(gTmp), gTmp)

	return
}

//

func WriteMeta(pw *io.PipeWriter, ci *CipherInfo, m *Meta) (n int64, err error) {
	dB(nil, "* WriteMeta")

	setGTmp2(0)

	// meta meta
	EncodeMetaU(&gTmp2, ID_POSITION, uint64(m.Position))

	// common
	EncodeMetaB(&gTmp2, ID_PATH, []byte(m.Path))
	EncodeMetaU(&gTmp2, ID_MODE, uint64(m.Mode))
	EncodeMetaU(&gTmp2, ID_SIZE, uint64(m.Size))
	EncodeMetaU(&gTmp2, ID_MTIME, uint64(m.Mtime))
	EncodeMetaU(&gTmp2, ID_MTIME_NS, uint64(m.MtimeNs))

	EncodeMetaSys(&gTmp2, ci, m)

	dB(nil, "  WriteMeta: raw-meta[%x]", len(gTmp2))

	if oP.Encrypt {
		err = EncryptBinary(&gTmp, gTmp2, ci, false)
		if err != nil {
			return
		}
		dB(nil, "  WriteMeta: enc-meta[%x]", len(gTmp))
		n, err = WriteElementB(pw, ID_META_DATA, gTmp)
	} else {
		n, err = WriteElement(pw, gTmp2)
	}

	dB(err, "  WriteMeta: %#v", m)

	return
}

//

func WriteData(pw *io.PipeWriter, ci *CipherInfo, m *Meta) (n int64, err error) {
	dB(nil, "* WriteData")
	// raw(r) -> zip(w) -> split -> encrypt
	//        -> hash(w)

	flag := os.O_RDONLY
	if oP.NoAtime {
		//		flag |= syscall.O_NOATIME
		flag |= SYSCALL_O_NOATIME
	}
	var f *os.File
	f, err = os.OpenFile(m.PathSrc, flag, 0600)
	defer f.Close()
	if err != nil {
		return
	}
	err = lockFile(f, false)
	if err != nil {
		eMsg(E_WARN, err, "")
	}

	raw_r := bufio.NewReader(f)

	//
	enc_r, enc_w := io.Pipe()

	// hash
	hash_w := NewHash(ci)()

	// compress
	go Zip(ci, raw_r, enc_r, enc_w, hash_w)

	setGTmp2(SIZE_BINARY_MAX - 1024*1024)

	var last bool
	var k int
	var l int64
	for last == false {
		k, err = io.ReadFull(enc_r, gTmp2)
		if err == nil {
			dB(nil, "  WriteData: ReadFull[%x]", k)
		} else {
			dB(nil, "  WriteData: ReadFull[%x] err=%s", k, err)
		}

		if err == io.ErrClosedPipe {
			last = true
		}

		gTmp2 = gTmp2[:k]

		dB(nil, "  WriteData: raw-data[%x]", len(gTmp2))

		gtmp := gTmp2
		if oP.Encrypt {
			err = EncryptBinary(&gTmp, gTmp2, ci, false)
			if err != nil {
				return
			}
			gtmp = gTmp
		}

		l, err = WriteElementB(pw, ID_DATA, gtmp)
		n += l
		if err != nil {
			return
		}

		dB(nil, "  WriteData: enc-data[%x]", len(gtmp))
	}

	m.Hash = append(m.Hash[:0], hash_w.Sum(nil)...)
	dB(nil, "  WriteData: Hash[%x]=%x\n", len(m.Hash), m.Hash)

	if oP.Sign {
		m.Signature, err = SignHash(m.Hash, ci)
		if err != nil {
			return
		}
	}

	m.SizeEnc = n

	return
}

//

func WritePost(pw *io.PipeWriter, ci *CipherInfo, m *Meta) (n int64, err error) {
	dB(nil, "* WritePost")

	setGTmp2(0)

	if (os.FileMode(m.Mode)).IsRegular() {
		EncodeMetaB(&gTmp2, ID_HASH, m.Hash)
		if oP.Sign {
			EncodeMetaB(&gTmp2, ID_SIGNATURE, m.Signature)
		}
		EncodeMetaU(&gTmp2, ID_SIZE_ENC, uint64(m.SizeEnc))

		dB(nil, "  WritePost: raw-meta[%x]", len(gTmp2))
	}

	hm := NewHash(ci)()
	hm.Write(mTmp)
	m.HashMeta = append(m.HashMeta[:0], hm.Sum(nil)...)
	EncodeElementB(&gTmp2, ID_HASH_META, m.HashMeta)
	dB(nil, "  WritePost: HashMeta[%x]=%x", len(m.HashMeta), m.HashMeta)

	if oP.Encrypt {
		err = EncryptBinary(&gTmp, gTmp2, ci, false)
		if err != nil {
			return
		}
		dB(nil, "  WritePost: enc-meta[%x]", len(gTmp))
		n, err = WriteElementB(pw, ID_META_DATA, gTmp)
	} else {
		n, err = WriteElement(pw, gTmp2)
	}

	dB(nil, "  WritePost: %#v", m)
	return
}

//

func WriteEof(pw *io.PipeWriter, size int64) (n int64, err error) {
	dB(nil, "* WriteEof")

	n, err = WriteElementU0(pw, ID_EOF, uint64(size))

	dB(nil, "  WriteEof: %x", size)
	return
}

// L3.. func

//
func EncryptBinary(ct *[]byte, pt []byte, ci *CipherInfo, kek bool) error {
	dB(nil, "- EncryptBinary")

	if kek && (ci.EncryptKey != nil) {
		h := sha512.New()
		IncrementNonce(ci)
		c, err := rsa.EncryptOAEP(h, rand.Reader, ci.EncryptKey.(*rsa.PublicKey), pt, ci.Nonce)
		*ct = append((*ct)[:0], c...)
		return err
	}

	e, err := NewAead(ci, kek)
	if err != nil {
		return err
	}

	IncrementNonce(ci)
	*ct = append((*ct)[:0], ci.Nonce[:e.NonceSize()]...)
	*ct = e.Seal(*ct, ci.Nonce, pt, nil)

	dB(nil, "    raw[%x] %x\n", len(pt), pt)
	dB(nil, "    enc[%x] %x\n", len(*ct), *ct)
	return nil
}

//

func appendMetaList(meta *Meta) {
	metaList = append(metaList, *meta)
	dB(nil, "- appendMetaList: %x, %s", meta.Position, meta.Path)
	//	dB(nil, "  appendMetaList: %#v", metaList)
}

//

func getMetaData(m *Meta, path string, fi os.FileInfo) error {
	m.PathSrc = path
	m.Path = cleanPath(path)
	m.Mode = uint32(fi.Mode())
	m.Size = fi.Size()
	m.Mtime = fi.ModTime().Unix()
	m.MtimeNs = int64(fi.ModTime().Nanosecond())

	getMetaDataSys(m, path, fi)

	return nil
}

//

func EncodeMetaU(o *[]byte, id uint32, u uint64) {
	l := len(mTmp)
	setMTmp(l + 8)
	binary.BigEndian.PutUint64(mTmp[l:], u)
	EncodeElementU(o, id, u)
}

//

func EncodeMetaB(o *[]byte, id uint32, b []byte) {
	mTmp = append(mTmp, b...)
	EncodeElementB(o, id, b)
}
