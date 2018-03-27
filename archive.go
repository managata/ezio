//
//
//

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

//

func walkDir(pw *io.PipeWriter, ci *CipherInfo, path string, pos int64) (n int64, err error) {
	var l int64

	var fl []os.FileInfo
	fl, err = ioutil.ReadDir(path)
	if err != nil {
		eMsg(E_ERR, err, "")
		return
	}

	for _, v := range fl {
		p := filepath.Join(path, v.Name())
		l, err = WriteFilm(pw, ci, p, pos)
		pos += l
		n += l
		if err != nil {
			eMsg(E_ERR, err, "")
			if !oP.IgnoreError {
				return
			}
		}

		if v.IsDir() {
			l, err = walkDir(pw, ci, p, pos)
			pos += l
			n += l
			if err != nil {
				if !oP.IgnoreError {
					return
				}
			}
		}
	}

	return
}

//

func CreateArchive() {
	var w *os.File
	var err error

	// out archive
	//
	// 0 ezio -a
	// 1 ezio -a -f xxx
	// 2 ezio -a > yyy
	// 3 ezio -a -f xxx > yyy
	//
	// 4 ezio -a -c
	// 5 ezio -a -c -f xxx
	// 6 ezio -a -c > yyy
	// 7 ezio -a -c -f xxx > yyy
	//
	// 0 error
	// 1,3 use xxx
	// // 2 use stdout
	// 2 error
	//
	// 4 error
	// 5, 7 err
	// 6 use stdout

	if len(oP.File) > 0 {
		if oP.UseStdOut {
			eMsg(E_CRIT, nil, "both -c and -f specified")
		}
		if isLpathPresent(oP.File) {
			if !oP.Overwrite {
				eMsg(E_CRIT, os.ErrExist, "'%s'", oP.File)
			}
			err := os.RemoveAll(oP.File)
			if err != nil {
				eMsg(E_CRIT, err, "'%s'", oP.File)
			}
		}
		w, err = os.Create(oP.File)
		defer w.Close()
		if err != nil {
			eMsg(E_CRIT, err, "'%s'", oP.File)
		}
		err = lockFile(w, true)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
	} else {
		if oP.UseStdOut && !terminal.IsTerminal(int(os.Stdout.Fd())) {
			w = os.Stdout
		} else {
			eMsg(E_CRIT, nil, "archive not specified")
		}
	}

	wc := make(chan bool)
	bw := bufio.NewWriter(w)
	pr, pw := io.Pipe()
	if oP.ErasureCode {
		go WriteArchiveEx(bw, pr, wc)
	} else {
		go WriteArchive(bw, pr, wc)
	}

	ci := new(CipherInfo)
	InitializeCipher(ci)
	if oP.Encrypt && (ci.EncryptKey == nil) {
		GenerateSalt(ci)
		GenerateKek(ci)
		ErasePass(ci, false)
	}

	var n int64
	var pos int64
	if len(oP.FileS) > 0 {
		for _, v := range oP.FileS {
			n, err = WriteFilm(pw, ci, v, pos)
			pos += n
			if err != nil {
				eMsg(E_ERR, err, "")
				if !oP.IgnoreError {
					return
				}
			}
			if isLdirPresent(v) {
				n, err = walkDir(pw, ci, v, pos)
				pos += n
				if err != nil {
					if !oP.IgnoreError {
						return
					}
				}
			}
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			v := sc.Text()
			n, err := WriteFilm(pw, ci, v, pos)
			pos += n
			if err != nil {
				eMsg(E_ERR, err, "")
				if !oP.IgnoreError {
					return
				}
			}
		}
		err := sc.Err()
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
	}

	if oP.MetaList {
		n, err := WriteMetaList(pw, ci)
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		pos += n
	}

	if oP.ErasureCode {
		r := oP.BlockSize - int(pos%int64(oP.BlockSize))
		if r < 16 {
			r += oP.BlockSize
		}
		n, err := WritePad(pw, r)
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		pos += n
	}

	//	bw.Flush()
	pw.Close()
	wc <- true

	if oP.ErasureCode {
		wc2 := make(chan bool)
		pr, pw = io.Pipe()
		go WriteArchive(bw, pr, wc2)
		//
		WriteErasureCode(pw, pos)
		pw.Close()
		wc2 <- true
	}

	w.Close()
}

//

func ExtractArchive() {
	var err error

	// out directory/file
	//
	// 0 ezio -x
	// 1 ezio -x -d xxx
	// 2 ezio -x > yyy
	// 3 ezio -x -d xxx > yyy
	//
	// 4 ezio -x -c
	// 5 ezio -x -c -d xxx
	// 6 ezio -x -c > yyy
	// 7 ezio -x -c -d xxx > yyy
	//
	// 0,2 use ./
	// 1,3 use xxx
	//
	// 4 error
	// 5,7 error
	// 6 use stdout

	// out
	pipe := !terminal.IsTerminal(int(os.Stdout.Fd()))

	if len(oP.ExtractDir) == 0 {
		if oP.UseStdOut {
			if pipe {
				oP.StdOut = true
			} else {
				eMsg(E_CRIT, nil, "-c specified but no pipe exists")
			}
		} else {
			oP.ExtractDir = "./"
		}
	} else {
		if oP.UseStdOut {
			eMsg(E_CRIT, nil, "both -c and -d specified")
		}
	}

	if oP.StdOut {
		if oP.Position < 0 {
			oP.Position = 0
		}
	} else {
		if isPathPresent(oP.ExtractDir) {
			if !isDirPresent(oP.ExtractDir) {
				eMsg(E_CRIT, os.ErrExist, "'%s'", oP.ExtractDir)
			}
		} else {
			err := os.MkdirAll(oP.ExtractDir, 0777)
			if err != nil {
				eMsg(E_CRIT, err, "'%s'", oP.ExtractDir)
			}
		}
	}

	var ar *Reader
	var r *os.File

	if oP.StdIn {
		ar = NewReader(FwdSeeker(os.Stdin))
	} else {
		if !isRegularPresent(oP.File) {
			eMsg(E_CRIT, os.ErrNotExist, "'%s'", oP.File)
		}

		r, err = os.Open(oP.File)
		defer r.Close()
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		err = lockFile(r, false)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
		ar = NewReader(r)
	}

	if oP.Position > 0 {
		_, err = ar.Discard(int(oP.Position))
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
	}

	ci := new(CipherInfo)
	InitializeCipher(ci)

	for {
		err = ExtractFilm(ar, ci)
		if err == io.EOF {
			break
		}
		if err == errNotError {
			err = nil
		}
		if err == errNotErrorButDicard {
			DiscardFilm(ar)
			err = nil
		}
		if err != nil {
			eMsg(E_ERR, err, "")
			if !oP.IgnoreError {
				break
			}
		}

		if oP.Position >= 0 {
			break
		}
	}

	RestoreDirTime()
}

//

func ListArchive(hint bool) {
	var err error

	var ar *Reader
	var r *os.File

	if oP.StdIn {
		ar = NewReader(FwdSeeker(os.Stdin))
	} else {
		if !isRegularPresent(oP.File) {
			eMsg(E_CRIT, os.ErrNotExist, "'%s'", oP.File)
		}

		r, err = os.Open(oP.File)
		defer r.Close()
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		err = lockFile(r, false)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
		ar = NewReader(r)
	}

	if oP.Position > 0 {
		_, err = ar.Discard(int(oP.Position))
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
	}

	ci := new(CipherInfo)
	InitializeCipher(ci)

	if hint && ExtractMetaList(ar, ci) {
	} else {
		for {
			err = ExtractFilm(ar, ci)
			if err == io.EOF {
				break
			}
			if err == errNotError {
				err = nil
			}
			if err == errNotErrorButDicard {
				DiscardFilm(ar)
				err = nil
			}
			if err != nil {
				eMsg(E_ERR, err, "")
				if !oP.IgnoreError {
					break
				}
			}

			if oP.Position >= 0 {
				break
			}
		}
	}

	for _, m := range metaList {
		mode := os.FileMode(m.Mode)

		switch oP.ListType {
		case 0:
			eMsg(E_PATH, nil, "%s", m.Path)
		case 1:
			eMsg(E_PATH, nil, "%d %s", m.Position, m.Path)
		case 2:
			eMsg(E_PATH, nil, "%-11s %7d %s %7d %s", mode.String(), m.Size, time.Unix(m.Mtime, 0).Format("2006-01-02 15:04:05"), m.Position, m.Path)
		case 3:
			ft := "regular file"
			switch mode & os.ModeType {
			case os.ModeDir:
				ft = "directory"
			case os.ModeSymlink:
				ft = "symbolic link"
			case os.ModeNamedPipe:
				ft = "fifo"
			case os.ModeDevice:
				if mode&os.ModeCharDevice == os.ModeCharDevice {
					ft = "character special file"
				} else {
					ft = "block special file"
				}
			}
			eMsg(E_PATH, nil, "  File: ‘%s’", m.Path)
			eMsg(E_STATUS, nil, "  Size: %-15d SizeEnc: %-15d %s", m.Size, m.SizeEnc, ft)
			eMsg(E_STATUS, nil, "Device: %-15d Inode: %-11d Links: %d", m.Device, m.Inode, m.Nlink)
			eMsg(E_STATUS, nil, "Access: (%04o/%s)  Uid: %-6d Gid: %-6d", mode&os.ModePerm, mode.String(), m.Uid, m.Gid)
			eMsg(E_STATUS, nil, "Access: %s", time.Unix(m.Atime, m.AtimeNs).Format("2006-01-02 15:04:05.000000000 -0700"))
			eMsg(E_STATUS, nil, "Modify: %s", time.Unix(m.Mtime, m.MtimeNs).Format("2006-01-02 15:04:05.000000000 -0700"))
			eMsg(E_STATUS, nil, "Change: %s", time.Unix(m.Ctime, m.CtimeNs).Format("2006-01-02 15:04:05.000000000 -0700"))
			eMsg(E_STATUS, nil, " Birth: -")
			eMsg(E_STATUS, nil, "   Pos: %d", m.Position)
			eMsg(E_STATUS, nil, "")
		case 4:
			json, _ := json.Marshal(m)
			eMsg(E_PATH, nil, "%s", string(json))
		default:
			eMsg(E_PATH, nil, "%s", m.Path)
		}
	}

}

//

func TestArchive() {
	var err error

	var r *os.File
	var ar *Reader

	var w *os.File
	var bw *bufio.Writer

	if oP.StdIn {
		if oP.ErasureCode {
			eMsg(E_CRIT, nil, "-r must specify with -f")
		}
		ar = NewReader(FwdSeeker(os.Stdin))
	} else {
		if !isRegularPresent(oP.File) {
			eMsg(E_CRIT, os.ErrNotExist, "'%s'", oP.File)
		}

		r, err = os.Open(oP.File)
		defer r.Close()
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		err = lockFile(r, false)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
		ar = NewReader(r)
	}

	if oP.ErasureCode {
		pos, err := ExtractErasureCode(ar)
		if err != nil {
			eMsg(E_CRIT, err, "")
		}

		w, err = os.Create(oP.File + ".rep")
		defer w.Close()
		if err != nil {
			eMsg(E_CRIT, err, "")
		}
		err = lockFile(w, true)
		if err != nil {
			eMsg(E_WARN, err, "")
		}
		bw = bufio.NewWriter(w)

		RepairBlock(bw, ar, pos)

		bw.Flush()
		w.Close()

		eMsg(E_NOTICE, nil, "'%s' created", oP.File+".rep")

		return
	}

	ExtractArchive()
}

////

func WriteArchive(bw *bufio.Writer, pr *io.PipeReader, wc chan bool) {
	dB(nil, "@ WriteArcive")

	n, err := io.Copy(bw, pr)
	dB(err, "  @ WriteArcive: copied %x", n)

	bw.Flush()
	_ = <-wc
}
