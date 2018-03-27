//
//
//

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash/adler32"
	"hash/crc32"
	"io"

	"github.com/templexxx/reedsolomon"
)

//

var ecHash []uint32 = make([]uint32, 0, 128*128)
var ecParity [][]byte = make([][]byte, 0, 2*128)

//

func WriteArchiveEx(bw *bufio.Writer, pr *io.PipeReader, wc chan bool) {
	dB(nil, "@ WriteArchiveEx")
	var err error

	bs := oP.BlockSize
	data := oP.BlockData
	parity := oP.BlockParity

	buf := make([][]byte, data+parity)
	for i := 0; i < data+parity; i++ {
		buf[i] = make([]byte, bs)
	}
	hash := make([]uint32, data)

	//
	var enc reedsolomon.Encoder
	enc, err = reedsolomon.New(data, parity)

	var i int
	var n int
	fin := false

	for !fin {
		for i = 0; i < data; i++ {
			n, err = io.ReadFull(pr, buf[i])
			if n < bs {
				fin = true
				break
			}
			if err != nil {
				fin = true
				break
			}
			// write
			bw.Write(buf[i][:])
			// hash
			hash[i] = crc32.ChecksumIEEE(buf[i][:])
		}
		// ec
		if !fin {
			ecHash = append(ecHash, hash...)
			enc.Encode(buf)
			for l := data; l < data+parity; l++ {
				tmp := make([]byte, bs)
				copy(tmp, buf[l])
				ecParity = append(ecParity, tmp)
			}
		}
	}

	//	dB(nil, "ecParity[%d] %x\n", len(ecParity), ecParity)

	// write
	bw.Write(buf[i][:n])

	// zero fill
	for k := n; k < bs; k++ {
		buf[i][k] = 0
	}
	hash[i] = adler32.Checksum(buf[i][:])

	for j := i + 1; j < data; j++ {
		for k := 0; k < bs; k++ {
			buf[j][k] = 0
		}
		// hash
		hash[i] = crc32.ChecksumIEEE(buf[i][:])
	}
	// ec
	ecHash = append(ecHash, hash...)
	err = enc.Encode(buf)
	dB(err, "# encode: err=")
	for l := data; l < data+parity; l++ {
		ecParity = append(ecParity, buf[l])
	}

	bw.Flush()

	_ = <-wc
}

//

func WriteErasureCode(pw *io.PipeWriter, pos int64) (n int64, err error) {
	dB(nil, "# WriteErasureCode")

	var l int64
	l, err = WriteMagic(pw)
	n += l
	if err != nil {
		return
	}

	cc := len(ecHash) / oP.BlockData
	cp := len(ecParity) / oP.BlockParity
	if cc != cp {
		eMsg(E_CRIT, nil, "  WriteErasureCode: %d, %d", cc, cp)
	}

	l, err = WriteElementU(pw, ID_BLOCK_SIZE, uint64(oP.BlockSize))
	n += l
	if err != nil {
		return
	}
	l, err = WriteElementU(pw, ID_BLOCK_DATA, uint64(oP.BlockData))
	n += l
	if err != nil {
		return
	}
	l, err = WriteElementU(pw, ID_BLOCK_PARITY, uint64(oP.BlockParity))
	n += l
	if err != nil {
		return
	}

	setGTmp(4 * oP.BlockData)
	s := 0
	t := 0
	for i := 0; i < cc; i++ {
		for j := 0; j < oP.BlockData; j++ {
			binary.BigEndian.PutUint32(gTmp[4*j:], ecHash[s])
			s++
		}
		l, err = WriteElementB(pw, ID_CHECK_SUM, gTmp)
		n += l
		if err != nil {
			return
		}
		for j := 0; j < oP.BlockParity; j++ {
			p := ecParity[t]
			l, err = WriteElementB(pw, ID_PARITY, p)
			n += l
			if err != nil {
				return
			}
			t++
		}
	}

	l, err = WriteEof(pw, n)
	n += l

	return
}

//

func ExtractErasureCode(ar *Reader) (pos int64, err error) {
	//	defer ar.Seek(0, io.SeekStart)

	var l int64
	var id uint32
	var n int64

	var f bool
	f, pos = SearchErasureCode(ar)
	if !f {
		err = errors.New("erasure code NOT found")
		return
	}
	eMsg(E_INFO, nil, "erasure code found!")

	id, _, l, err = ReadElementM(ar)
	n += l
	if id != ID_MAGIC {
		return
	}

	var u uint64
	id, u, n, err = ReadElementU(ar)
	n += l
	if (id != ID_BLOCK_SIZE) || (err != nil) {
		return
	}
	oP.BlockSize = int(u)

	id, u, l, err = ReadElementU(ar)
	n += l
	if (id != ID_BLOCK_DATA) || (err != nil) {
		return
	}
	oP.BlockData = int(u)

	id, u, l, err = ReadElementU(ar)
	n += l
	if (id != ID_BLOCK_PARITY) || (err != nil) {
		return
	}
	oP.BlockParity = int(u)

	cs := int64(oP.BlockSize * oP.BlockData)
	cc := int(pos / cs)
	cr := int(pos % cs)
	if cr != 0 {
		cc++
	}

	// setGTmp(4 * oP.BlockData)
	// setGTmp2(oP.BlockSize)

	dB(nil, "pos=%x bs=%x cc=%x cr=%x\n", pos, oP.BlockSize, cc, cr)

	for i := 0; i < cc; i++ {
		id, l, err = ReadElementB(ar, &gTmp)
		n += l
		if (id != ID_CHECK_SUM) || (len(gTmp) != 4*oP.BlockData) || (err != nil) {
			return
		}

		for j := 0; j < oP.BlockData; j++ {
			ecHash = append(ecHash, binary.BigEndian.Uint32(gTmp[4*j:]))
		}
		for j := 0; j < oP.BlockParity; j++ {
			p := make([]byte, 0, oP.BlockSize)
			id, l, err = ReadElementB(ar, &p)
			n += l
			if (id != ID_PARITY) || (len(p) != oP.BlockSize) || (err != nil) {
				return
			}
			ecParity = append(ecParity, p)
		}
	}

	return
}

//

func RepairBlock(bw *bufio.Writer, ar *Reader, pos int64) (err error) {
	dB(nil, "# VerifyBlock")
	ar.Seek(0, io.SeekStart)

	bs := oP.BlockSize
	data := oP.BlockData
	parity := oP.BlockParity

	buf := make([][]byte, data+parity)
	for i := 0; i < data; i++ {
		buf[i] = make([]byte, bs)
	}

	cs := int64(oP.BlockSize * oP.BlockData)
	cc := int(pos / cs)
	cr := int(pos%cs) / oP.BlockSize

	dB(nil, "pos=%x bs=%x cc=%x cr=%x", pos, oP.BlockSize, cc, cr)

	var enc reedsolomon.Encoder
	enc, err = reedsolomon.New(data, parity)

	n := 0
	s := 0
	t := 0
	for i := 0; i < cc; i++ {
		for j := 0; j < data; j++ {
			n, err = io.ReadFull(ar, buf[j])
			dB(nil, "# VerifyBlock n=%x err=%s", n, err)
			if (n != bs) || (err != nil) {
				return
			}
			// hash check
			hash := crc32.ChecksumIEEE(buf[j])
			if hash != ecHash[t] {
				eMsg(E_WARN, nil, "damaged block found")
				buf[j] = nil
			}
			t++
		}
		for j := 0; j < parity; j++ {
			buf[data+j] = ecParity[s]
			s++
		}
		err = enc.Reconstruct(buf)
		dB(nil, "# reconstruct: i=%x err=%s", i, err)
		if err != nil {
			eMsg(E_CRIT, err, "can not repair")
		}
		for j := 0; j < data; j++ {
			_, err = bw.Write(buf[j])
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}
	}

	if cr > 0 {
		for j := 0; j < cr; j++ {
			n, err = io.ReadFull(ar, buf[j])
			dB(nil, "# VerifyBlock n=%x err=%s", n, err)
			if (n != bs) || (err != nil) {
				return
			}
			// hash check
			hash := crc32.ChecksumIEEE(buf[j])
			if hash != ecHash[t] {
				eMsg(E_WARN, nil, "damaged block found")
				buf[j] = nil
			}
			t++
		}
		for j := cr; j < data; j++ {
			dB(nil, "# VerifyBlock zerofill j=%x", j)
			for k := 0; k < bs; k++ {
				buf[j][k] = 0
			}
		}
		for j := 0; j < parity; j++ {
			buf[data+j] = ecParity[s]
			s++
		}

		err = enc.Reconstruct(buf)
		dB(nil, "# reconstruct: err=%s", err)
		for j := 0; j < cr; j++ {
			_, err = bw.Write(buf[j])
			if err != nil {
				eMsg(E_CRIT, err, "")
			}
		}
	}

	_, err = io.Copy(bw, ar)

	return
}
