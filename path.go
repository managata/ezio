//
//
//

package main

import (
	"os"
)

//

func isLpathPresent(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func isPathPresent(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isLdirPresent(p string) bool {
	s, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsDir()
}

func isDirPresent(p string) bool {
	s, err := os.Stat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsDir()
}

func isLregularPresent(p string) bool {
	s, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsRegular()
}

func isRegularPresent(p string) bool {
	s, err := os.Stat(p)
	if err != nil {
		return false
	}
	return s.Mode().IsRegular()
}
