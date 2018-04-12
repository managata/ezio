//
//
//

package main

import (
	"bufio"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/akmistry/go-lz4"
	"github.com/dsnet/compress/bzip2"
	//	"github.com/DataDog/zstd"
	"github.com/managata/zstd"
	"github.com/remyoudompheng/go-liblzma"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	errPublicNotFound  = errors.New("not valid public key")
	errPrivateNotFound = errors.New("not valid private key")
	errUnknownAlg      = errors.New("unknown alogorithm")
)

type CipherInfo struct {
	Suite []byte
	//
	Pass       []byte
	EncryptKey interface{}
	DecryptKey interface{}
	Kek        []byte
	KekSalt    []byte
	//
	Cek       []byte
	Nonce     []byte
	NonceMask uint64
	//
	SignPass  []byte
	SignKey   interface{}
	VerifyKey interface{}
}

const (
	CS_VER = iota
	CS_COMP
	CS_LEVEL
	CS_AEAD
	CS_HASH
	CS_RESERVE1
	CS_RESERVE2
	CS_RESERVE3
	CS_MAX
)

const (
	SIZE_SUITE      = CS_MAX
	SIZE_NONCE      = 12
	SIZE_NONCE_MASK = 8
	SIZE_SIGNATURE  = 8192
)

const (
	COMP_NONE  = 0
	COMP_ZSTD  = 1
	COMP_LZ4   = 2
	COMP_XZ    = 3
	COMP_GZIP  = 4
	COMP_BZIP2 = 5
)

const (
	AEAD_NONE              = 0
	AEAD_AES256_GCM        = 1
	AEAD_CHACHA20_POLY1305 = 2
)

const (
	HASH_NONE   = 0
	HASH_SHA256 = byte(crypto.SHA256)
	HASH_SHA512 = byte(crypto.SHA512)
)

var hashRaw []byte
var hashDec []byte
var hashMeta []byte
var sigNature []byte

//

func InitializeCipher(ci *CipherInfo) {
	dB(nil, "- InitializeCipher")
	var err error

	// allocate memory
	if cap(ci.Suite) < SIZE_SUITE {
		ci.Suite = make([]byte, SIZE_SUITE)
	}

	if cap(ci.Nonce) < SIZE_NONCE {
		ci.Nonce = make([]byte, SIZE_NONCE)
	}

	// default 1-ZSTD-3-AES256-GCM-SHA256
	ci.Suite[CS_VER] = 1
	ci.Suite[CS_COMP] = COMP_ZSTD
	ci.Suite[CS_LEVEL] = 3
	ci.Suite[CS_AEAD] = AEAD_AES256_GCM
	ci.Suite[CS_HASH] = HASH_SHA256

	if len(oP.CompType) > 0 {
		switch oP.CompType[:1] {
		case "z":
			ci.Suite[CS_COMP] = COMP_ZSTD
		case "l":
			ci.Suite[CS_COMP] = COMP_LZ4
		case "x":
			ci.Suite[CS_COMP] = COMP_XZ
		case "g":
			ci.Suite[CS_COMP] = COMP_GZIP
		case "b":
			ci.Suite[CS_COMP] = COMP_BZIP2
		}
	}

	if oP.CompLevel > 0 {
		ci.Suite[CS_LEVEL] = byte(oP.CompLevel)
	}

	switch ci.Suite[CS_COMP] {
	case COMP_ZSTD:
		if oP.CompLevel < 1 {
			ci.Suite[CS_LEVEL] = 3
		}
		if oP.CompLevel > 19 {
			ci.Suite[CS_LEVEL] = 19
		}
	case COMP_LZ4:
		if oP.CompLevel < 1 {
			ci.Suite[CS_LEVEL] = 1
		}
		if oP.CompLevel > 16 {
			ci.Suite[CS_LEVEL] = 16
		}
	case COMP_XZ:
		if oP.CompLevel < 1 {
			ci.Suite[CS_LEVEL] = 6
		}
		if oP.CompLevel > 9 {
			ci.Suite[CS_LEVEL] = 9
		}
	case COMP_GZIP:
		if oP.CompLevel < 1 {
			ci.Suite[CS_LEVEL] = 6
		}
		if oP.CompLevel > 9 {
			ci.Suite[CS_LEVEL] = 9
		}
	case COMP_BZIP2:
		if oP.CompLevel < 1 {
			ci.Suite[CS_LEVEL] = 9
		}
		if oP.CompLevel > 9 {
			ci.Suite[CS_LEVEL] = 9
		}
	}

	if len(oP.EncType) > 0 {
		switch oP.EncType[:1] {
		case "a":
			ci.Suite[CS_AEAD] = AEAD_AES256_GCM
		case "c":
			ci.Suite[CS_AEAD] = AEAD_CHACHA20_POLY1305
		}
	}

	if len(oP.HashType) > 0 {
		switch oP.HashType[:1] {
		case "2":
			ci.Suite[CS_HASH] = HASH_SHA256
		case "5":
			ci.Suite[CS_HASH] = HASH_SHA512
		}
	}

	if !oP.Compress {
		ci.Suite[CS_COMP] = COMP_NONE
	}
	if !oP.Encrypt {
		ci.Suite[CS_AEAD] = AEAD_NONE
	}

	// key file
	if oP.Archive {
		if oP.Encrypt {
			if len(oP.EncryptKey) != 0 {
				err = ReadPublicKey(ci, oP.EncryptKey, false)
			} else {
				err = GetPass(ci, false)
			}
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}

		if oP.Sign {
			err = ReadPrivateKey(ci, oP.SignKey, true)
			ErasePass(ci, true)
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}
	} else {
		if len(oP.DecryptKey) != 0 {
			err = ReadPrivateKey(ci, oP.DecryptKey, false)
			ErasePass(ci, false)
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}
		if len(oP.VerifyKey) != 0 {
			err = ReadPublicKey(ci, oP.VerifyKey, true)
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}
	}

	// Nonce Mask
	if ci.NonceMask == 0 {
		m := make([]byte, SIZE_NONCE_MASK)
		if l, err := rand.Read(m); (err != nil) || (l != SIZE_NONCE_MASK) {
			eMsg(E_CRIT, err, "can not get rand")
			return
		}
		ci.NonceMask = binary.BigEndian.Uint64(m)
		m = m[:0]
		m = nil
	}

	// Nonce
	GenerateNonce(ci)

	s := GetHashSize(ci)
	if cap(hashRaw) < s {
		hashRaw = make([]byte, 0, s)
	}
	if cap(hashDec) < s {
		hashDec = make([]byte, 0, s)
	}
	if cap(hashMeta) < s {
		hashMeta = make([]byte, 0, s)
	}

	if cap(sigNature) < SIZE_SIGNATURE {
		sigNature = make([]byte, 0, SIZE_SIGNATURE)
	}
}

//

func GetHashSize(ci *CipherInfo) int {
	return crypto.Hash(ci.Suite[CS_HASH]).Size()
}

//

func GetKeySize(ci *CipherInfo) int {
	switch ci.Suite[CS_AEAD] {
	case AEAD_AES256_GCM:
		return 32
	case AEAD_CHACHA20_POLY1305:
		return 32
	}
	return 0
}

//

func GenerateSalt(ci *CipherInfo) {
	dB(nil, "- GenerateSalt")

	ci.KekSalt = make([]byte, GetHashSize(ci))

	n, err := rand.Read(ci.KekSalt)
	dB(nil, "  n=%x ci.KekSalt[%x] err=%s", n, len(ci.KekSalt), err)
	if (n != len(ci.KekSalt)) || (err != nil) {
		eMsg(E_CRIT, err, "GenerateSalt")
	}
}

//

func GenerateKek(ci *CipherInfo) {
	dB(nil, "- GenerateKek:")

	if ci.Pass == nil {
		err := GetPass(ci, false)
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
	}

	h := NewHash(ci)
	hkdf := hkdf.New(h, ci.Pass, ci.KekSalt, nil)

	s := GetKeySize(ci)
	if len(ci.Kek) < s {
		ci.Kek = make([]byte, s)
	} else {
		ci.Kek = ci.Kek[:s]
	}

	n, err := io.ReadFull(hkdf, ci.Kek)
	dB(nil, "  ci.Kek[%x]", len(ci.Kek))
	if n != len(ci.Kek) || err != nil {
		eMsg(E_CRIT, err, "GenerateKek")
		return
	}

	return
}

//

func GenerateCek(ci *CipherInfo) {
	dB(nil, "- GenerateCek")

	s := GetKeySize(ci)
	if len(ci.Cek) < s {
		ci.Cek = make([]byte, s)
	} else {
		ci.Cek = ci.Cek[:s]
	}

	n, err := rand.Read(ci.Cek)
	dB(nil, "  ci.KEK[%x]", len(ci.Cek))
	if n != len(ci.Cek) || err != nil {
		eMsg(E_CRIT, err, "GenerateCek")
		return
	}

	return
}

//

func ErasePass(ci *CipherInfo, sign bool) {
	pass := &ci.Pass
	if sign {
		pass = &ci.SignPass
	}
	for i := 0; i < len(*pass); i++ {
		(*pass)[i] = 0
	}
	*pass = nil
}

//

func GenerateNonce(ci *CipherInfo) {
	if l, err := rand.Read(ci.Nonce[:4]); (err != nil) || (l != 4) {
		eMsg(E_CRIT, err, "can not get rand")
		return
	}
	binary.BigEndian.PutUint64(ci.Nonce[4:], ci.NonceMask)

	return
}

//

func IncrementNonce(ci *CipherInfo) {
	c := binary.BigEndian.Uint64(ci.Nonce[4:])
	c = c ^ ci.NonceMask
	c++
	c = c ^ ci.NonceMask

	binary.BigEndian.PutUint64(ci.Nonce[4:], c)

	return
}

//

func NewHash(ci *CipherInfo) func() hash.Hash {
	switch ci.Suite[CS_HASH] {
	case HASH_SHA256:
		return sha256.New
	case HASH_SHA512:
		return sha512.New
	}
	return sha256.New
}

//

func Zip(ci *CipherInfo, raw_r *bufio.Reader, enc_r *io.PipeReader, enc_w *io.PipeWriter, hash_w hash.Hash) {
	switch ci.Suite[CS_COMP] {
	case COMP_NONE:
		hash_enc_w := io.MultiWriter(hash_w, enc_w)
		io.Copy(hash_enc_w, raw_r)
	case COMP_ZSTD:
		var zip_w *zstd.Writer
		if len(oP.Dictionary) > 0 {
			zip_w = zstd.NewWriterLevelDict(enc_w, int(ci.Suite[CS_LEVEL]), []byte(oP.Dictionary))
		} else {
			zip_w = zstd.NewWriterLevel(enc_w, int(ci.Suite[CS_LEVEL]))
		}
		hash_zip_w := io.MultiWriter(hash_w, zip_w)
		io.Copy(hash_zip_w, raw_r)
		zip_w.Close()
	case COMP_LZ4:
		zip_w := lz4.NewWriter(enc_w)
		hash_zip_w := io.MultiWriter(hash_w, zip_w)
		io.Copy(hash_zip_w, raw_r)
		zip_w.Close()
	case COMP_XZ:
		zip_w, _ := xz.NewWriter(enc_w, xz.Preset(ci.Suite[CS_LEVEL]))
		hash_zip_w := io.MultiWriter(hash_w, zip_w)
		io.Copy(hash_zip_w, raw_r)
		zip_w.Close()
	case COMP_GZIP:
		zip_w, _ := gzip.NewWriterLevel(enc_w, int(ci.Suite[CS_LEVEL]))
		hash_zip_w := io.MultiWriter(hash_w, zip_w)
		io.Copy(hash_zip_w, raw_r)
		zip_w.Close()
	case COMP_BZIP2:
		zip_w, _ := bzip2.NewWriter(enc_w, &bzip2.WriterConfig{Level: bzip2.BestCompression})
		hash_zip_w := io.MultiWriter(hash_w, zip_w)
		io.Copy(hash_zip_w, raw_r)
		zip_w.Close()
	}

	enc_r.Close()
}

//

func UnZip(ci *CipherInfo, hash_bw_w io.Writer, zip_r *io.PipeReader, wc chan bool) {
	switch ci.Suite[CS_COMP] {
	case COMP_NONE:
		io.Copy(hash_bw_w, zip_r)
	case COMP_ZSTD:
		var unzip_r io.ReadCloser
		if len(oP.Dictionary) > 0 {
			unzip_r = zstd.NewReaderDict(zip_r, []byte(oP.Dictionary))
		} else {
			unzip_r = zstd.NewReader(zip_r)
		}
		io.Copy(hash_bw_w, unzip_r)
		unzip_r.Close()
	case COMP_LZ4:
		unzip_r := lz4.NewReader(zip_r)
		io.Copy(hash_bw_w, unzip_r)
		unzip_r.Close()
	case COMP_XZ:
		unzip_r, _ := xz.NewReader(zip_r)
		io.Copy(hash_bw_w, unzip_r)
		unzip_r.Close()
	case COMP_GZIP:
		unzip_r, _ := gzip.NewReader(zip_r)
		io.Copy(hash_bw_w, unzip_r)
		unzip_r.Close()
	case COMP_BZIP2:
		unzip_r, _ := bzip2.NewReader(zip_r, new(bzip2.ReaderConfig))
		io.Copy(hash_bw_w, unzip_r)
		unzip_r.Close()
	}

	// bw.Flush()
	_ = <-wc
}

//

func NewAead(ci *CipherInfo, kek bool) (cipher.AEAD, error) {
	k := ci.Cek
	if kek {
		k = ci.Kek
	}

	switch ci.Suite[CS_AEAD] {
	case AEAD_AES256_GCM:
		if len(k) < 32 {
			return nil, os.ErrInvalid
		}
		c, err := aes.NewCipher(k[:32])
		if err != nil {
			return nil, os.ErrInvalid
		}
		return cipher.NewGCM(c)
	case AEAD_CHACHA20_POLY1305:
		if len(k) < chacha20poly1305.KeySize {
			return nil, os.ErrInvalid
		}
		return chacha20poly1305.New(k[:chacha20poly1305.KeySize])
	}
	return nil, os.ErrInvalid
}

//

func ReadPrivateKey(ci *CipherInfo, path string, sign bool) (err error) {
	dB(nil, "- ReadPrivateKey: pass=%x sign=%x", path, sign)
	key := &ci.DecryptKey
	pass := &ci.Pass
	if sign {
		key = &ci.SignKey
		pass = &ci.SignPass
	}

	defer func() {
		if err != nil {
			*key = nil
		}
	}()

	var d []byte
	d, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}

	for {
		b, r := pem.Decode(d)
		if b == nil {
			err = errPrivateNotFound
			return
		}

		if x509.IsEncryptedPEMBlock(b) {
			dB(nil, "  ReadPrivateKey: x509.IsEncryptedPEMBlock")
			if *pass == nil {
				err = GetPass(ci, sign)
				if err != nil {
					return
				}
			}
			dB(nil, "  ReadPrivateKey: ci.pass=%x", ci.Pass)
			b.Bytes, err = x509.DecryptPEMBlock(b, *pass)
			if err != nil {
				return
			}
		}

		dB(nil, "  ReadPrivateKey: xb.Type %s", b.Type)

		switch b.Type {
		case "RSA PRIVATE KEY":
			*key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return
			}
			(*key).(*rsa.PrivateKey).Precompute()
			err = (*key).(*rsa.PrivateKey).Validate()
			return
		case "EC PRIVATE KEY":
			*key, err = x509.ParseECPrivateKey(b.Bytes)
			return
		case "PRIVATE KEY":
			var ki interface{}
			ki, err = x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				return
			}
			var ok bool
			*key, ok = ki.(*rsa.PrivateKey)
			if !ok {
				return errPrivateNotFound
			}
			(*key).(*rsa.PrivateKey).Precompute()
			err = (*key).(*rsa.PrivateKey).Validate()
			return
		}

		if len(r) == 0 {
			err = errPrivateNotFound
			return
		}
		d = r
	}

	return
}

//

func ReadPublicKey(ci *CipherInfo, path string, sign bool) (err error) {
	key := &ci.EncryptKey
	if sign {
		key = &ci.VerifyKey
	}

	defer func() {
		if err != nil {
			*key = nil
		}
	}()

	var d []byte
	d, err = ioutil.ReadFile(path)
	if err != nil {
		return
	}

	for {
		b, r := pem.Decode(d)
		if b == nil {
			err = errPublicNotFound
			return
		}

		switch b.Type {
		case "PUBLIC KEY":
			*key, err = x509.ParsePKIXPublicKey(b.Bytes)
			return
		case "CERTIFICATE":
			var c *x509.Certificate
			c, err = x509.ParseCertificate(b.Bytes)
			*key = c.PublicKey
			return
		}

		if len(r) == 0 {
			err = errPublicNotFound
			return
		}
		d = r
	}

	return
}

//

func SignHash(h []byte, ci *CipherInfo) (sig []byte, err error) {
	switch ci.SignKey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPSS(rand.Reader, ci.SignKey.(*rsa.PrivateKey), crypto.Hash(ci.Suite[CS_HASH]), h, nil)
	case *ecdsa.PrivateKey:
		sig, err = ci.SignKey.(*ecdsa.PrivateKey).Sign(rand.Reader, h, nil)
	default:
		err = errUnknownAlg
	}
	return
}

//

func VerifyHash(h []byte, sig []byte, ci *CipherInfo) (ok bool) {
	switch ci.VerifyKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPSS(ci.VerifyKey.(*rsa.PublicKey), crypto.Hash(ci.Suite[CS_HASH]), h, sig, nil)
		return err == nil
	case *ecdsa.PublicKey:
		var s struct {
			R, S *big.Int
		}
		_, err := asn1.Unmarshal(sig, &s)
		if err != nil {
			eMsg(E_ERR, err, "")
			return false
		}
		return ecdsa.Verify(ci.VerifyKey.(*ecdsa.PublicKey), h, s.R, s.S)
	}
	return false
}

//

func GetPass(ci *CipherInfo, sign bool) (err error) {
	defer func() {
		if err != nil {
			ci.Pass = nil
		}
	}()

	file := oP.PassFile
	fd := oP.PassFd
	pass := &ci.Pass
	if sign {
		file = oP.SignPassFile
		fd = oP.SignPassFd
		pass = &ci.SignPass
	}

	if len(file) > 0 {
		*pass, err = ioutil.ReadFile(file)
		return
	}

	if fd >= 3 {
		var f *os.File
		//		f, err = os.Open(fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd))
		// if err != nil {
		// 	return
		// }
		f = os.NewFile(uintptr(fd), "fdn")
		*pass, err = ioutil.ReadAll(f)
		return
	}

	if oP.StdIn {
		eMsg(E_CRIT, nil, "pass input required but stdin is busy")
	}

	if sign {
		fmt.Fprint(os.Stderr, "Sign ")
	}
	fmt.Fprint(os.Stderr, "Pass: ")
	//	*pass, err = terminal.ReadPassword(int(syscall.Stdin))
	*pass, err = terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	if (err == nil) && (len(*pass) == 0) {
		*pass = make([]byte, 0)
	}

	return
}
