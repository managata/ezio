//
//
//

package main

import (
	"encoding/binary"
	"errors"
	"io"
)

//

var eTmp = make([]byte, 0, 16)

func setETmp(l int) {
	eTmp = eTmp[:l]
}

func clearETmp() {
	l := len(eTmp)
	for i := 0; i < l; i++ {
		eTmp[i] = 0
	}
}

var eTmp2 = make([]byte, 0, 16)

func setETmp2(l int) {
	eTmp2 = eTmp2[:l]
}

func clearETmp2() {
	l := len(eTmp2)
	for i := 0; i < l; i++ {
		eTmp2[i] = 0
	}
}

//

func WriteElement(o *io.PipeWriter, b []byte) (int64, error) {
	l, err := o.Write(b)
	return int64(l), err
}

//

func WriteElementU0(o *io.PipeWriter, id uint32, u uint64) (int64, error) {
	var err error
	var total int
	var n int

	n, err = o.Write(idToVid(id))
	total += n
	if err != nil {
		return int64(total), err
	}
	n, err = o.Write(sizeToVsize(uint64(8)))
	total += n
	if err != nil {
		return int64(total), err
	}

	setETmp(8)
	binary.BigEndian.PutUint64(eTmp, u)
	n, err = o.Write(eTmp)
	total += n
	return int64(total), err
}

//

func WriteElementU(o *io.PipeWriter, id uint32, u uint64) (int64, error) {
	l, err := o.Write(idToVid(id))
	if err != nil {
		return int64(l), err
	}
	m, err := o.Write(uintToVuint(u))
	return int64(l + m), err
}

//

func WriteElementB(o *io.PipeWriter, id uint32, b []byte) (int64, error) {
	l, err := o.Write(idToVid(id))
	if err != nil {
		return int64(l), err
	}
	m, err := o.Write(sizeToVsize(uint64(len(b))))
	if err != nil {
		return int64(l + m), err
	}
	n, err := o.Write(b)
	return int64(l + m + n), err
}

//

func WriteElementM(o *io.PipeWriter, id uint32, size uint64) (int64, error) {
	l, err := o.Write(idToVid(id))
	if err != nil {
		return int64(l), err
	}
	m, err := o.Write(sizeToVsize(size))
	return int64(l + m), err
}

//

func EncodeElementU(o *[]byte, id uint32, u uint64) {
	*o = append(*o, idToVid(id)...)
	*o = append(*o, uintToVuint(u)...)
}

//

func EncodeElementB(o *[]byte, id uint32, b []byte) {
	*o = append(*o, idToVid(id)...)
	*o = append(*o, sizeToVsize(uint64(len(b)))...)
	*o = append(*o, b...)
}

//

func EncodeElementM(o *[]byte, id uint32, size uint64) {
	*o = append(*o, idToVid(id)...)
	*o = append(*o, sizeToVsize(size)...)
}

//

func idToVid(id uint32) []byte {
	if id > 0xFFFFFFE {
		eMsg(E_WARN, nil, "idToVid: Element ID is too big")
	}
	return toVint(uint64(id))
}

//

func sizeToVsize(size uint64) []byte {
	if size == SIZE_UNKNOWN {
		return []byte{0xFF}
	}
	return toVint(size)
}

//

func uintToVuint(ui uint64) []byte {
	vi := make([]byte, 9, 9)
	binary.BigEndian.PutUint64(vi[1:], ui)

	i := 1
	for ; i < 8; i++ {
		if (vi[i] & 0xFF) != 0 {
			break
		}
	}
	s := 9 - i
	vi[i-1] = 0x80 + byte(s)

	return vi[i-1:]
}

//

func toVint(ui uint64) []byte {
	if ui > 0xFFFFFFFFFFFFFE {
		eMsg(E_WARN, nil, "toVint: uint value is too big")
		return nil
	}

	var width int
	var mark byte
	var shift byte

	switch {
	case ui < 0x7F:
		width = 1
		mark = 0x80
		shift = 56
	case ui < 0x3FFF:
		width = 2
		mark = 0x40
		shift = 48
	case ui < 0x1FFFFF:
		width = 3
		mark = 0x20
		shift = 40
	case ui < 0xFFFFFFF:
		width = 4
		mark = 0x10
		shift = 32
	case ui < 0x7FFFFFFFF:
		width = 5
		mark = 0x08
		shift = 24
	case ui < 0x3FFFFFFFFFF:
		width = 6
		mark = 0x04
		shift = 16
	case ui < 0x1FFFFFFFFFFFF:
		width = 7
		mark = 0x02
		shift = 8
	case ui < 0xFFFFFFFFFFFFFF:
		width = 8
		mark = 0x01
		shift = 0
	}

	vi := make([]byte, 8, 8)
	binary.BigEndian.PutUint64(vi, ui<<shift)
	vi[0] = vi[0] | mark
	return vi[:width]
}

////

func PeekElementId(ar *Reader) (id uint32, n int64, err error) {
	vl, err := ar.Peek(1)
	if err != nil {
		return ID_NULL, 0, err
	}

	l := toWidth(vl[0])
	if l == 0 {
		return ID_NULL, 0, errors.New("PeekElementId: ID length is zero")
	}
	if l > 4 {
		return ID_NULL, 0, errors.New("PeekElementId: ID length is too long")
	}

	vi, err := ar.Peek(l)
	if err != nil {
		return ID_NULL, 0, err
	}
	if len(vi) != l {
		return ID_NULL, 0, errors.New("PeekElementId: can not read enough length")
	}

	id, n = vidToId(vi)
	return
}

//

func ReadElementId(ar *Reader) (id uint32, n int64, err error) {
	vl, err := ar.Peek(1)
	if err != nil {
		return ID_NULL, 0, err
	}

	l := toWidth(vl[0])
	if l == 0 {
		return ID_NULL, 0, errors.New("ReadElementId: ID length is zero")
	}
	if l > 4 {
		return ID_NULL, 0, errors.New("ReadElementId: ID length is too long")
	}

	setETmp(l)
	m, err := io.ReadFull(ar, eTmp)
	if err != nil {
		return ID_NULL, int64(m), err
	}
	if m != l {
		return ID_NULL, int64(m), errors.New("ReadElementId: can not read enough length")
	}

	id, n = vidToId(eTmp)
	return
}

//

func ReadElementSize(ar *Reader) (size uint64, n int64, err error) {
	vl, err := ar.Peek(1)
	if err != nil {
		return ID_NULL, 0, err
	}

	l := toWidth(vl[0])
	if l == 0 {
		return 0, 0, errors.New("ReadElementSize: size length is zero")
	}

	setETmp(l)
	m, err := io.ReadFull(ar, eTmp)
	if err != nil {
		return 0, int64(m), err
	}
	if m != l {
		return 0, int64(m), errors.New("ReadElementSize: can not read enough length")
	}

	size, n = vsizeToSize(eTmp)
	return
}

//

// return uint64, readbyte
func ReadElementU(ar *Reader) (id uint32, u uint64, n int64, err error) {
	var l int
	var m int64
	var size uint64

	id, m, err = ReadElementId(ar)
	n = m
	if err != nil {
		return ID_NULL, 0, n, err
	}

	size, m, err = ReadElementSize(ar)
	n += m
	if (size > 8) || (size == 0) {
		err = errors.New("ReadElementU: element size is invalid")
	}
	if err != nil {
		return ID_NULL, 0, n, err
	}

	setETmp(8)
	clearETmp()
	l, err = io.ReadFull(ar, eTmp[8-size:8])
	n += int64(l)
	if err != nil {
		return ID_NULL, 0, n, err
	}
	if uint64(l) != size {
		return ID_NULL, 0, n, errors.New("ReadElementU: can not read enough length")
	}

	dB(err, ".   ReadElementU: id=%x(%s) u=%x n=%x size=%x", id, EI[id].Name, binary.BigEndian.Uint64(eTmp), n, size)

	// return id, binary.BigEndian.Uint64(tmp), n, nil
	return id, binary.BigEndian.Uint64(eTmp), n, nil
}

//

// read binary type element from Reader
//   in ar *Reader
//   inout b *[]byte
//   out id uint32
//   out n int64
func ReadElementB(ar *Reader, b *[]byte) (id uint32, n int64, err error) {
	var l int
	var m int64
	var size uint64

	id, m, err = ReadElementId(ar)
	n = m
	if err != nil {
		return id, n, err
	}

	size, m, err = ReadElementSize(ar)
	n += m
	if size > uint64(SIZE_BINARY_MAX) {
		err = errors.New("ReadElementB: element size is invalid")
	}
	if err != nil {
		return id, n, err
	}

	if cap(*b) < int(size) {
		ar.Discard(int(size))
		n += int64(size)
		return id, n, errors.New("ReadElementB: B slice is too small")
	}

	*b = (*b)[:size]
	l, err = io.ReadFull(ar, *b)
	n += int64(l)
	if uint64(l) != size {
		err = errors.New("ReadElementB: can not read enough size of binary")
	}
	if err != nil {
		return id, n, err
	}

	dB(err, ".   ReadElementB: id=%x(%s) b[%x] n=%x", id, EI[id].Name, size, n)

	return id, n, nil
}

//

// read master type element from Reader
//   in ar *Reader
//   out id uint32
//   out size uint64
//   out n int64
func ReadElementM(ar *Reader) (id uint32, size uint64, n int64, err error) {
	var m int64

	id, m, err = ReadElementId(ar)
	n = m
	if err != nil {
		return id, 0, n, err
	}

	size, m, err = ReadElementSize(ar)
	n += m
	if size == 0 {
		err = errors.New("ReadElementM: element size is invalid")
	}
	if err != nil {
		return id, size, n, err
	}

	return id, size, n, nil
}

//

//
//
func DiscardElement(ar *Reader) (id uint32, size uint64, n int64, err error) {
	var m int64

	id, m, err = ReadElementId(ar)
	n = m
	if err != nil {
		return id, 0, n, err
	}

	size, m, err = ReadElementSize(ar)
	n += m
	if err != nil {
		return id, size, n, err
	}

	if size == SIZE_UNKNOWN {
		return id, size, n, err
	}

	//	var p int64
	_, err = ar.Discard(int(size))
	n += int64(size)
	if err != nil {
		return id, size, n, err
	}

	return id, size, n, nil
}

//

func DiscardFilm(ar *Reader) (n uint64, err error) {
	var id uint32
	var m int64

	id, _, err = PeekElementId(ar)
	if err != nil {
		return 0, err
	}

	for id != ID_MAGIC {
		_, _, m, err = DiscardElement(ar)
		n += uint64(m)
		if err != nil {
			return n, err
		}
		id, _, err = PeekElementId(ar)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

//

// convert VINT ID to ID
//   in vi []byte; ID:VINT[1..4]
//   out size uint64; UINT64[8]{0..0xFFFFFFE,..max}
//   out width int64; INT[4,8]{1..4,..8,0}
func vidToId(vi []byte) (uint32, int64) {
	id, n := toUint(vi)
	if id > 0xFFFFFFE {
		eMsg(E_WARN, nil, "VintToId: Element ID is too big")
		id = 0
	}
	return uint32(id), n
}

//

// convert VINT SIZE to SIZE
//   in vi []byte; SIZE:VINT[1..8]
//   out size uint64; UINT64[8]{0..vintmax,unknown}
//   out width int64; INT[4,8]{1..8,0}
func vsizeToSize(vi []byte) (uint64, int64) {
	if vi[0] == 0xFF {
		return SIZE_UNKNOWN, 1
	}

	size, n := toUint(vi)
	return size, n
}

//

// convert VUINT part of Element to UINT64
//   in vu []byte; SIZE:VINT[1]{0x81..0x88}+UINT64[1..8]{0..max}
//   out ui uint64; UINT64[8]{0..max}
//   out length int64; INT[4,8]{2..9,0}
func vuintToUint(vu []byte) (uint64, int64) {
	s := vu[0] ^ 0x80
	if (s < 1) || (s > 8) {
		eMsg(E_WARN, nil, "VuintToUint: uint size is too long")
		return 0, 0
	}

	setETmp2(8)
	clearETmp2()
	copy(eTmp2[8-s:], vu[1:])
	return binary.BigEndian.Uint64(eTmp2), int64(s) + 1
}

//

// convert VINT to UINT64
//   in vi []byte; VINT[1..8] := (VHEAD+VDATA)[1..8]{0..max}
//   out ui uint64; UINT64[8]{0..vintmax}
//   out width int64; INT[4,8]{1..8,0}
func toUint(vi []byte) (uint64, int64) {
	mask := byte(0x80)
	i := 1
	for ; i < 9; i++ {
		if (vi[0] & mask) != 0 {
			break
		}
		mask = mask >> 1
	}

	if i == 9 {
		eMsg(E_WARN, nil, "toUint: invalid VINT value")
		return 0, 0
	}

	setETmp2(8)
	clearETmp2()
	copy(eTmp2[8-i:], vi)
	eTmp2[8-i] ^= mask
	return binary.BigEndian.Uint64(eTmp2), int64(i)
}

//

// get VINT width
//   in v byte; VHEAD[1]{0x01..0xff}
//   out width int; INT[4,8]{1..8,0}
func toWidth(v byte) int {
	mask := byte(0x80)
	i := 1
	for ; i < 9; i++ {
		if (v & mask) != 0 {
			break
		}
		mask = mask >> 1
	}

	if i == 9 {
		eMsg(E_WARN, nil, "toWidth: invalid VINT length")
		return 0
	}

	return i
}
