//
//
// +build debug

package main

import "fmt"

func dB(err error, f string, a ...interface{}) {
	c := "@: "
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
