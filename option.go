//
//
//

package main

import (
	"fmt"
	"os"
	"regexp"

	flags "github.com/jessevdk/go-flags"
	"golang.org/x/crypto/ssh/terminal"
)

type Options struct {
	Archive bool `short:"a" long:"archive" description:"Archive files"`
	Extract bool `short:"x" long:"extract" description:"Extract files"`
	List    bool `short:"l" long:"list" description:"List files"`
	View    bool `short:"v" long:"view" description:"View files"`
	Test    bool `short:"t" long:"test" description:"Test files"`

	File  string   `short:"f" long:"file" description:"archive name to process"`
	FileS []string `no-flag:"true"`

	Encrypt  bool `short:"e" long:"encrypt" description:"encrypt files"`
	Compress bool `short:"z" long:"compress" description:"compress files"`
	Sign     bool `no-flag:"true" description:"sign files"`

	MetaList bool `short:"m" long:"meta-list" description:"append metadata list for quick access"`
	ListType int  `short:"L" long:"list-type" default:"-1" description:"[0-4] listing style"`

	UseStdOut  bool   `short:"c" long:"stdout" description:"output archive/file to stdout, logs to stderr"`
	ExtractDir string `short:"d" long:"extract-dir" description:"directory to which to extract files"`
	Overwrite  bool   `short:"W" long:"overwrite" description:"overwrite existing files"`
	Position   int64  `short:"p" long:"position" default:"-1" description:"extract a file starting from the position"`

	NoAtime bool `short:"U" long:"preserve-atime" description:"preserve atime (Linux only)"`

	Exclude    string         `long:"exclude" description:"exclude files matching regexp pattern. evaluate before --include"`
	Include    string         `long:"include" description:"include files matching regexp pattern"`
	ExcludeReg *regexp.Regexp `no-flag:"true"`
	IncludeReg *regexp.Regexp `no-flag:"true"`

	LogFile     string `short:"o" long:"log-file" description:"write logs to file"`
	LogLevel    int    `short:"O" long:"log-level" description:"[-1|0|1|2|3|4|5|6|7] log level" default:"5"`
	Quiet       bool   `short:"q" long:"quiet" description:"same as --log-level=-1"`
	IgnoreError bool   `long:"ignore-error" description:"continue as much as possible"`

	CompType   string `short:"Z" long:"compress-type" description:"[z|l|x|g|b] compression algorithm (zstd|lz4|xz|gzip|bzip2) " default:"zstd"`
	CompLevel  int    `short:"G" long:"compress-level" description:"compression level"`
	Dictionary string `short:"D" long:"dictionary" description:"doctionary file for zstd (not implemented)"`
	EncType    string `short:"E" long:"encrypt-type" description:"[a|c] encryption algorithm (aes256-gcm|chacha20-poly1305)" default:"aes256-gcm"`
	HashType   string `short:"H" long:"hash-type" description:"[2|5] hash algorithm (sha256|sha512)" default:"sha256"`

	PassFile   string `long:"pass-file" description:"read pass from file"`
	PassFd     int    `long:"pass-fd" description:"read pass from file descriptor"`
	EncryptKey string `long:"encrypt-key" description:"public key or certification file for encryption"`
	DecryptKey string `long:"decrypt-key" description:"private key file for decryption"`

	SignPassFile string `long:"sign-pass-file" description:"file which contain pass for --sign-key file"`
	SignPassFd   int    `long:"sign-pass-fd" description:"file descriptor from which read pass for --sign-key file (UNIX only)"`
	SignKey      string `long:"sign-key" description:"private keyfile for signing"`
	VerifyKey    string `long:"verify-key" description:"public key or certification file for verification"`

	ErasureCode bool `short:"r" long:"erasure-code" description:"append erasure core"`
	BlockSize   int  `long:"block-size" description:"erasure code block size" default:"4096"`
	BlockData   int  `long:"block-data" description:"erasure code data block count" default:"128"`
	BlockParity int  `long:"block-parity" description:"erasure code parity block count" default:"2"`

	Version bool `long:"version" description:"print version"`

	StdIn  bool `no-flag:"true" default:"false"`
	StdOut bool `no-flag:"true" default:"false"`
}

var oP Options
var version string

//

func parseFlags() {
	parser := flags.NewParser(&oP, flags.Default)
	parser.Name = "ezio"
	parser.Usage = `[ -axlvt ] [OPTIONS...] [-f ARCHIVE-FILE] [FILE]...`
	args, err := parser.Parse()

	if err != nil {
		//		fmt.Fprint(os.Stderr, "ezio: %s\n", err)
		os.Exit(1)
	}

	if oP.Version {
		fmt.Fprintf(os.Stderr, "ezio: %s\n", version)
		os.Exit(0)
	}

	m := 0
	if oP.Archive {
		m++
	}
	if oP.Extract {
		m++
	}
	if oP.List {
		m++
	}
	if oP.View {
		m++
	}
	if oP.Test {
		m++
	}
	if m != 1 {
		fmt.Fprint(os.Stderr, "ezio: select one of the options: -a -x -l -v -t\n")
		os.Exit(1)
	}

	// input file validation
	oP.FileS = args
	pipe := !terminal.IsTerminal(int(os.Stdin.Fd()))

	if oP.Archive {
		if !pipe && (len(oP.FileS) == 0) {
			fmt.Fprint(os.Stderr, "ezio: file(s) to archive not specified\n")
			os.Exit(1)
		}
	} else {
		if len(oP.FileS) > 0 {
			fmt.Fprint(os.Stderr, "ezio: file(s) specified but not allowed\n")
			os.Exit(1)
		}

		// in archive
		//
		// 0 ezio -x
		// 1 ezio -x -f xxx
		// 2 yyy | ezio -x
		// 3 yyy | ezio -x -f xxx
		//
		// 0,3 error
		// 1 use xxx
		// 2 use yyy
		if len(oP.File) > 0 {
			if pipe {
				fmt.Fprint(os.Stderr, "ezio: both -f and stdin exist for input archive\n")
				os.Exit(1)
			}
		} else {
			if pipe {
				oP.StdIn = true
				if oP.List {
					oP.List = false
					oP.View = true
				}
			} else {
				fmt.Fprint(os.Stderr, "no archive specified\n")
				os.Exit(1)
			}
		}
	}

	// ListType
	if oP.List && (oP.ListType < 0) {
		oP.ListType = 0
	}

	if oP.List && (oP.ListType > 2) {
		oP.ListType = 2
	}

	if oP.View && (oP.ListType < 0) {
		oP.ListType = 2
	}

	// cipher
	if oP.Archive {
		if len(oP.EncryptKey) != 0 {
			oP.Encrypt = true
		}
		if len(oP.SignKey) != 0 {
			oP.Sign = true
		}
	}

	//
	if oP.Quiet {
		oP.LogLevel = -1
	}

	// regexp
	if len(oP.Exclude) > 0 {
		oP.ExcludeReg, err = regexp.Compile(oP.Exclude)
		if err != nil {
			fmt.Fprint(os.Stderr, "ezio: --exclude regexp pattern invalid\n")
			os.Exit(1)
		}
	}
	if len(oP.Include) > 0 {
		oP.IncludeReg, err = regexp.Compile(oP.Include)
		if err != nil {
			fmt.Fprint(os.Stderr, "ezio: --include regexp pattern invalid\n")
			os.Exit(1)
		}
	}

	// block
	if oP.BlockSize < 32 {
		fmt.Fprint(os.Stderr, "ezio: --block-size too smail. min 32\n")
		os.Exit(1)
	}
	if oP.BlockSize > 1024*1024 {
		fmt.Fprint(os.Stderr, "ezio: --block-size too large. max 1048510\n")
		os.Exit(1)
	}
	if oP.BlockData < 2 {
		fmt.Fprint(os.Stderr, "ezio: --block-data too smail. min 2\n")
		os.Exit(1)
	}
	if oP.BlockData > 256 {
		fmt.Fprint(os.Stderr, "ezio: --block-data too large. max 256\n")
		os.Exit(1)
	}
	if oP.BlockParity < 1 {
		fmt.Fprint(os.Stderr, "ezio: --block-parity too smail. min 1\n")
		os.Exit(1)
	}
	if oP.BlockParity > oP.BlockData {
		fmt.Fprint(os.Stderr, "ezio: --block-parity too large. max --block-data\n")
		os.Exit(1)
	}

}
