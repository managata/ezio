//
//
//

package main

import (
	"fmt"
	"os"
)

const (
	E_PATH    = 0
	E_STATUS  = 1
	E_CRIT    = 2
	E_ERR     = 3
	E_WARNING = 4
	E_NOTICE  = 5
	E_INFO    = 6
	E_DEBUG   = 7
	E_MAX     = 8

	E_WARN = 4
)

var eFile *os.File
var eCount [E_MAX]int

//

func eOpen() (err error) {
	if len(oP.LogFile) == 0 {
		if oP.UseStdOut {
			eFile = os.Stderr
		} else {
			eFile = os.Stdout
		}
		return
	}

	eFile, err = os.OpenFile(oP.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	return
}

//

func eClose() (err error) {
	if eFile == os.Stdout {
		return
	}
	eFile.Close()
	return
}

//

func eMsg(l int, err error, f string, a ...interface{}) {
	defer func() {
		//		if (l == E_CRIT) || (!oP.IgnoreError && (l == E_ERROR)) {
		if l == E_CRIT {
			os.Exit(1)
		}
	}()

	eCount[l]++

	if l > oP.LogLevel {
		return
	}

	c := ""
	switch l {
	case E_PATH:
	case E_STATUS:
	case E_CRIT:
		c = "C: "
	case E_ERR:
		c = "E: "
	case E_WARNING:
		c = "W: "
	case E_NOTICE:
		c = "N: "
	case E_INFO:
		c = "I: "
	case E_DEBUG:
		c = ""
	}
	fmt.Fprintf(eFile, "%s", c)

	if a == nil {
		fmt.Fprintf(eFile, f)
	} else {
		fmt.Fprintf(eFile, f, a...)
	}

	if err != nil {
		if len(f) != 0 {
			fmt.Fprintf(eFile, ": ")
		}
		fmt.Fprintf(eFile, "%s", err)
	}
	fmt.Fprintln(eFile)
}

//

func eStatus() {
	eMsg(E_DEBUG, nil,
		"\nTotal Files:%d Crit:%d Err:%d Warn:%d Notice:%d Info:%d",
		eCount[E_PATH],
		eCount[E_CRIT],
		eCount[E_ERR],
		eCount[E_WARNING],
		eCount[E_NOTICE],
		eCount[E_INFO],
	)
}
